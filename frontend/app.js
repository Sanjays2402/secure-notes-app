/* Vault frontend — talks to the Secure Notes HTTP API.
 *
 * >>> POST-DEPLOY CONFIG — set this once, then re-upload to S3 <<<
 * After `sam deploy --guided`, copy the `ApiEndpoint` output below.
 */
const API_BASE = "https://REPLACE_WITH_API_GATEWAY_URL"; // e.g. "https://abc123.execute-api.us-west-2.amazonaws.com"

const MAX_BODY = 100000;
const RECENT_KEY = "vault.recentNotes";

const $ = (id) => document.getElementById(id);

const els = {
  title: $("noteTitle"),
  body: $("noteBody"),
  seal: $("sealBtn"),
  count: $("charCount"),
  composeMsg: $("composeMsg"),
  idInput: $("noteId"),
  open: $("openBtn"),
  openMsg: $("openMsg"),
  view: $("noteView"),
  viewId: $("viewId"),
  viewDate: $("viewDate"),
  viewTitle: $("viewTitle"),
  viewBody: $("viewBody"),
  recent: $("recentList"),
  recentEmpty: $("recentEmpty"),
  keyStatus: $("keyStatus"),
};

function apiConfigured() {
  return !API_BASE.includes("REPLACE_WITH");
}

function setMsg(el, text, kind) {
  el.textContent = text;
  el.className = "msg" + (kind ? " " + kind : "");
}

async function api(path, options = {}) {
  if (!apiConfigured()) {
    throw new Error("API_BASE is not configured — paste the ApiEndpoint output from sam deploy into app.js");
  }
  const res = await fetch(API_BASE + path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data.error || `request failed (${res.status})`);
  }
  return data;
}

/* ---------- sealing ---------- */

els.body.addEventListener("input", () => {
  els.count.textContent = `${els.body.value.length.toLocaleString()} / ${MAX_BODY.toLocaleString()}`;
});

els.seal.addEventListener("click", async () => {
  const title = els.title.value.trim();
  const body = els.body.value;
  setMsg(els.composeMsg, "", "");
  if (!title || !body) {
    setMsg(els.composeMsg, "A title and a body are both required.", "error");
    return;
  }
  if (body.length > MAX_BODY) {
    setMsg(els.composeMsg, `Body is over the ${MAX_BODY.toLocaleString()}-character limit.`, "error");
    return;
  }
  els.seal.disabled = true;
  try {
    const { noteId } = await api("/notes", {
      method: "POST",
      body: JSON.stringify({ title, body }),
    });
    rememberNote(noteId, title);
    setMsg(els.composeMsg, `Sealed. Note ID: ${noteId}`, "ok");
    els.title.value = "";
    els.body.value = "";
    els.count.textContent = `0 / ${MAX_BODY.toLocaleString()}`;
    els.idInput.value = noteId;
  } catch (err) {
    setMsg(els.composeMsg, err.message, "error");
  } finally {
    els.seal.disabled = false;
  }
});

/* ---------- opening ---------- */

async function openNote(noteId) {
  setMsg(els.openMsg, "", "");
  els.view.classList.add("hidden");
  const id = (noteId || els.idInput.value).trim();
  if (!id) {
    setMsg(els.openMsg, "Paste a note ID first.", "error");
    return;
  }
  els.open.disabled = true;
  try {
    const note = await api(`/notes/${encodeURIComponent(id)}`);
    els.viewId.textContent = note.noteId;
    els.viewDate.textContent = note.createdAt ? new Date(note.createdAt).toLocaleString() : "";
    els.viewTitle.textContent = note.title;
    els.viewBody.textContent = note.body;
    els.view.classList.remove("hidden");
  } catch (err) {
    setMsg(els.openMsg, err.message, "error");
  } finally {
    els.open.disabled = false;
  }
}

els.open.addEventListener("click", () => openNote());
els.idInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") openNote();
});

/* ---------- recent notes (this browser only) ---------- */

function loadRecent() {
  try {
    return JSON.parse(localStorage.getItem(RECENT_KEY) || "[]");
  } catch {
    return [];
  }
}

function rememberNote(id, title) {
  const recent = loadRecent().filter((n) => n.id !== id);
  recent.unshift({ id, title, at: new Date().toISOString() });
  localStorage.setItem(RECENT_KEY, JSON.stringify(recent.slice(0, 20)));
  renderRecent();
}

function renderRecent() {
  const recent = loadRecent();
  els.recent.innerHTML = "";
  els.recentEmpty.style.display = recent.length ? "none" : "";
  for (const n of recent) {
    const li = document.createElement("li");
    const btn = document.createElement("button");
    btn.type = "button";
    const name = document.createElement("span");
    name.textContent = n.title;
    const rid = document.createElement("span");
    rid.className = "rid";
    rid.textContent = n.id.slice(0, 10) + "…";
    btn.append(name, rid);
    btn.addEventListener("click", () => {
      els.idInput.value = n.id;
      openNote(n.id);
    });
    li.append(btn);
    els.recent.append(li);
  }
}

renderRecent();

if (!apiConfigured()) {
  els.keyStatus.textContent = "API not configured — see app.js";
}
