"""SAM template smoke test — structure, least-privilege, no wildcards.

Parses template.yaml with a CloudFormation-tolerant loader (intrinsic tags
like !Ref/!Sub/!GetAtt are kept as opaque markers) and asserts the security
properties the project promises.
"""

import os

import pytest
import yaml


class _CfnLoader(yaml.SafeLoader):
    pass


def _unknown(loader, tag_suffix, node):
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    return loader.construct_mapping(node)


_CfnLoader.add_multi_constructor("!", _unknown)


@pytest.fixture(scope="module")
def template():
    path = os.path.join(os.path.dirname(__file__), "..", "template.yaml")
    with open(path) as fh:
        return yaml.load(fh, Loader=_CfnLoader)


@pytest.fixture(scope="module")
def resources(template):
    return template["Resources"]


def _statements(policy_doc):
    stmts = policy_doc.get("Statement", [])
    return stmts if isinstance(stmts, list) else [stmts]


def _actions(stmt):
    acts = stmt.get("Action", [])
    return acts if isinstance(acts, list) else [acts]


# --- structure ------------------------------------------------------------

def test_expected_resources_exist(resources):
    for name in ["NotesKey", "NotesTable", "NotesApi", "CreateNoteFunction",
                 "GetNoteFunction", "CreateNoteRole", "GetNoteRole",
                 "WebsiteBucket"]:
        assert name in resources, f"missing resource: {name}"


def test_lambdas_are_python312(resources):
    for fn in ["CreateNoteFunction", "GetNoteFunction"]:
        props = resources[fn]["Properties"]
        assert props["Runtime"] == "python3.12"
        assert props["CodeUri"] == "src/"


def test_api_routes(resources):
    events = []
    for fn in ["CreateNoteFunction", "GetNoteFunction"]:
        for ev in resources[fn]["Properties"]["Events"].values():
            events.append((ev["Properties"]["Path"], ev["Properties"]["Method"]))
    assert ("/notes", "POST") in events
    assert ("/notes/{id}", "GET") in events


def test_table_is_on_demand_with_noteid_pk(resources):
    props = resources["NotesTable"]["Properties"]
    assert props["BillingMode"] == "PAY_PER_REQUEST"
    keys = {k["AttributeName"]: k["KeyType"] for k in props["KeySchema"]}
    assert keys == {"noteId": "HASH"}


def test_key_rotation_enabled(resources):
    assert resources["NotesKey"]["Properties"]["EnableKeyRotation"] is True


# --- least privilege ------------------------------------------------------

def test_kms_key_policy_grants_lambdas_only_envelope_ops(resources):
    policy = resources["NotesKey"]["Properties"]["KeyPolicy"]
    lambda_stmts = [s for s in _statements(policy)
                    if s.get("Sid") == "AllowLambdaEnvelopeOperations"]
    assert len(lambda_stmts) == 1
    granted = set(_actions(lambda_stmts[0]))
    assert granted <= {"kms:GenerateDataKey", "kms:Decrypt"}, granted
    assert granted, "lambda key-policy statement grants nothing"


def test_no_kms_admin_for_lambdas(resources):
    policy = resources["NotesKey"]["Properties"]["KeyPolicy"]
    for stmt in _statements(policy):
        if stmt.get("Sid") == "AllowLambdaEnvelopeOperations":
            for act in _actions(stmt):
                assert act != "kms:*", "lambdas must not get kms:*"


def test_iam_roles_have_no_wildcard_actions(resources):
    for role in ["CreateNoteRole", "GetNoteRole"]:
        for pol in resources[role]["Properties"]["Policies"]:
            for stmt in _statements(pol["PolicyDocument"]):
                for act in _actions(stmt):
                    assert "*" not in act, f"{role} grants wildcard action {act}"
                    svc, _, _ = act.partition(":")
                    assert svc in {"kms", "dynamodb"}, f"{role} unexpected service {act}"


def test_create_role_cannot_decrypt_and_get_role_cannot_mint(resources):
    def inline_actions(role):
        acts = set()
        for pol in resources[role]["Properties"]["Policies"]:
            for stmt in _statements(pol["PolicyDocument"]):
                acts.update(_actions(stmt))
        return acts

    create_acts = inline_actions("CreateNoteRole")
    get_acts = inline_actions("GetNoteRole")
    assert "kms:GenerateDataKey" in create_acts
    assert "kms:Decrypt" not in create_acts, "create role must not unwrap keys"
    assert "kms:Decrypt" in get_acts
    assert "kms:GenerateDataKey" not in get_acts, "get role must not mint keys"
    assert "dynamodb:PutItem" in create_acts
    assert "dynamodb:GetItem" not in create_acts
    assert "dynamodb:GetItem" in get_acts
    assert "dynamodb:PutItem" not in get_acts


def test_no_hardcoded_credentials_in_template():
    path = os.path.join(os.path.dirname(__file__), "..", "template.yaml")
    text = open(path).read().lower()
    for needle in ["akia", "aws_secret", "password", "BEGIN PRIVATE KEY"]:
        assert needle not in text, f"suspicious string in template: {needle}"


# --- list endpoint / TTL ----------------------------------------------------

def test_list_function_and_route_exist(resources):
    assert "ListNotesFunction" in resources
    props = resources["ListNotesFunction"]["Properties"]
    assert props["Runtime"] == "python3.12"
    assert props["Handler"] == "list_notes/app.lambda_handler"
    events = [(e["Properties"]["Path"], e["Properties"]["Method"])
              for e in props["Events"].values()]
    assert ("/notes", "GET") in events


def test_list_role_has_scan_only_no_kms(resources):
    assert "ListNotesRole" in resources
    acts = set()
    for pol in resources["ListNotesRole"]["Properties"]["Policies"]:
        for stmt in _statements(pol["PolicyDocument"]):
            acts.update(_actions(stmt))
    assert "dynamodb:Scan" in acts
    assert not any(a.startswith("kms:") for a in acts), f"list role has KMS: {acts}"
    assert not any(a in {"dynamodb:PutItem", "dynamodb:GetItem"} for a in acts)


def test_table_has_ttl_on_expires_at(resources):
    ttl = resources["NotesTable"]["Properties"]["TimeToLiveSpecification"]
    assert ttl["AttributeName"] == "expiresAt"
    assert ttl["Enabled"] is True


def test_all_expected_routes_present(resources):
    events = []
    for fn in ["CreateNoteFunction", "GetNoteFunction", "ListNotesFunction"]:
        for ev in resources[fn]["Properties"]["Events"].values():
            events.append((ev["Properties"]["Path"], ev["Properties"]["Method"]))
    assert ("/notes", "POST") in events
    assert ("/notes", "GET") in events
    assert ("/notes/{id}", "GET") in events


def test_key_policy_avoids_role_getatt_cycle(resources):
    # The key policy must not !GetAtt the Lambda roles (that edge + the
    # roles' GetAtt on the key = circular dependency). Role ARNs are built
    # with !Sub from the explicit RoleNames instead.
    policy = resources["NotesKey"]["Properties"]["KeyPolicy"]
    principals = []
    for stmt in _statements(policy):
        if stmt.get("Sid") == "AllowLambdaEnvelopeOperations":
            p = stmt["Principal"]["AWS"]
            principals.extend(p if isinstance(p, list) else [p])
    assert len(principals) == 2
    for arn in principals:
        assert ":role/" in arn and "GetAtt" not in arn, arn
