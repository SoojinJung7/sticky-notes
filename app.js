import { initializeApp } from "https://www.gstatic.com/firebasejs/12.11.0/firebase-app.js";
import { getAuth, signInWithPopup, GoogleAuthProvider, signOut, onAuthStateChanged } from "https://www.gstatic.com/firebasejs/12.11.0/firebase-auth.js";
import { getFirestore, doc, getDoc, setDoc } from "https://www.gstatic.com/firebasejs/12.11.0/firebase-firestore.js";

const firebaseConfig = {
  apiKey: "AIzaSyAQ6H1_UdCaXAH2l4XqGuMGrt_ILAsUoIU",
  authDomain: "stickynote-b705d.firebaseapp.com",
  projectId: "stickynote-b705d",
  storageBucket: "stickynote-b705d.firebasestorage.app",
  messagingSenderId: "458922481738",
  appId: "1:458922481738:web:c8c00af9914089d9efeeb3",
  measurementId: "G-JZ5J3WW0KN"
};

const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const db = getFirestore(app);
const provider = new GoogleAuthProvider();

// ===== 상수 =====
const COLORS = [
  { name: '크림', hex: '#FCEAAA' },
  { name: '골드', hex: '#E8C86C' },
  { name: '연초록', hex: '#B8D9A0' },
  { name: '세이지', hex: '#8FBF7A' },
  { name: '초록', hex: '#6DA870' },
  { name: '진초록', hex: '#4A8C5E' },
  { name: '포레스트', hex: '#A8D5BA' },
  { name: '흰색', hex: '#FFFFFF' },
];

const STORAGE_KEY = 'sticky-notes-data';
const MODE_KEY = 'sticky-notes-mode';
const isMobile = window.innerWidth <= 600;

let notes = [];
let selectedColor = COLORS[0].hex;
let nextZ = 100;
let dragState = null;
let resizeState = null;
let saveTimeout = null;
let currentUser = null;
let authMode = localStorage.getItem(MODE_KEY); // 'google' | 'local' | null

// ===== Undo / Redo =====
const MAX_HISTORY = 50;
let undoStack = [];
let redoStack = [];
let inputSnapshotTimer = null;

function snapshotNotes() {
  return JSON.parse(JSON.stringify(notes));
}

function pushUndo() {
  undoStack.push(snapshotNotes());
  if (undoStack.length > MAX_HISTORY) undoStack.shift();
  redoStack = [];
  updateUndoRedoButtons();
}

function updateUndoRedoButtons() {
  const u = document.getElementById('undoBtn');
  const r = document.getElementById('redoBtn');
  if (u) u.disabled = undoStack.length === 0;
  if (r) r.disabled = redoStack.length === 0;
}

function doUndo() {
  if (undoStack.length === 0) return;
  redoStack.push(snapshotNotes());
  notes = undoStack.pop();
  renderAll();
  scheduleSave();
  updateUndoRedoButtons();
}

function doRedo() {
  if (redoStack.length === 0) return;
  undoStack.push(snapshotNotes());
  notes = redoStack.pop();
  renderAll();
  scheduleSave();
  updateUndoRedoButtons();
}

// ===== 암호화 (Web Crypto API + 비밀 문구 기반 키 동기화) =====
const CRYPTO_KEY_PREFIX = 'sticky-notes-key-';

function toBase64(buf) { return btoa(String.fromCharCode(...new Uint8Array(buf))); }
function fromBase64(b64) { return Uint8Array.from(atob(b64), c => c.charCodeAt(0)); }

// 비밀 문구 → PBKDF2 → AES 래핑 키 생성
async function deriveWrappingKey(passphrase, salt) {
  const enc = new TextEncoder().encode(passphrase);
  const baseKey = await crypto.subtle.importKey('raw', enc, 'PBKDF2', false, ['deriveKey']);
  return await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

// 암호화 키를 비밀 문구로 래핑하여 Firestore에 저장
async function wrapAndStoreKey(rawKeyB64, passphrase, hint, uid) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const wrappingKey = await deriveWrappingKey(passphrase, salt);
  const rawKeyBytes = fromBase64(rawKeyB64);
  const wrapped = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, wrappingKey, rawKeyBytes);
  const keyData = {
    salt: toBase64(salt),
    iv: toBase64(iv),
    wrappedKey: toBase64(wrapped),
  };
  if (hint) keyData.hint = hint;
  await setDoc(doc(db, 'userKeys', uid), keyData);
}

// Firestore에서 래핑된 키를 가져와 비밀 문구로 언래핑
async function unwrapKey(passphrase, uid) {
  const snap = await getDoc(doc(db, 'userKeys', uid));
  if (!snap.exists()) return null;
  const { salt, iv, wrappedKey } = snap.data();
  const wrappingKey = await deriveWrappingKey(passphrase, fromBase64(salt));
  try {
    const rawKeyBytes = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fromBase64(iv) },
      wrappingKey,
      fromBase64(wrappedKey)
    );
    return toBase64(rawKeyBytes);
  } catch {
    return null; // 비밀 문구 틀림
  }
}

// 비밀 문구 모달 표시 (Promise로 결과 반환)
function askPassphrase(isNew, hint) {
  return new Promise((resolve) => {
    const modal = document.getElementById('passphraseModal');
    const input = document.getElementById('ppInput');
    const confirm = document.getElementById('ppConfirm');
    const hintInput = document.getElementById('ppHintInput');
    const hintShow = document.getElementById('ppHintShow');
    const error = document.getElementById('ppError');
    const submit = document.getElementById('ppSubmit');
    const title = document.getElementById('ppTitle');
    const desc = document.getElementById('ppDesc');

    if (isNew) {
      title.textContent = '비밀 문구 설정';
      desc.textContent = '메모를 안전하게 암호화할 비밀 문구를 설정하세요. 다른 기기에서 로그인할 때 이 문구가 필요합니다.';
      confirm.style.display = '';
      hintInput.style.display = '';
      hintInput.value = '';
      hintShow.style.display = 'none';
    } else {
      title.textContent = '비밀 문구 입력';
      desc.textContent = '메모를 복호화하려면 처음 설정한 비밀 문구를 입력하세요.';
      confirm.style.display = 'none';
      hintInput.style.display = 'none';
      if (hint) {
        hintShow.textContent = '힌트: ' + hint;
        hintShow.style.display = 'block';
      } else {
        hintShow.style.display = 'none';
      }
    }

    input.value = '';
    confirm.value = '';
    error.style.display = 'none';
    modal.classList.remove('hidden');
    input.focus();

    const handler = () => {
      const val = input.value.trim();
      if (!val || val.length < 4) {
        error.textContent = '4자 이상 입력해주세요.';
        error.style.display = 'block';
        return;
      }
      if (isNew && val !== confirm.value.trim()) {
        error.textContent = '비밀 문구가 일치하지 않습니다.';
        error.style.display = 'block';
        return;
      }
      const hintVal = isNew ? hintInput.value.trim() : null;
      modal.classList.add('hidden');
      resolve({ passphrase: val, hint: hintVal });
    };
    submit.onclick = handler;
    input.onkeydown = (e) => { if (e.key === 'Enter') { if (isNew) confirm.focus(); else handler(); } };
    confirm.onkeydown = (e) => { if (e.key === 'Enter') { if (isNew) hintInput.focus(); else handler(); } };
    hintInput.onkeydown = (e) => { if (e.key === 'Enter') handler(); };
  });
}

// 암호화 키 가져오기 (로컬 캐시 → Firestore → 새로 생성)
async function getCryptoKey(uid) {
  const storageKey = CRYPTO_KEY_PREFIX + uid;
  let rawKeyB64 = localStorage.getItem(storageKey);

  if (rawKeyB64) {
    const keyBytes = fromBase64(rawKeyB64);
    return await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt', 'decrypt']);
  }

  // 로컬에 키가 없음 → Firestore에 래핑된 키가 있는지 확인
  const keySnap = await getDoc(doc(db, 'userKeys', uid));

  if (keySnap.exists()) {
    // 기존 유저: 비밀 문구로 키 복원
    const hint = keySnap.data().hint || '';
    let firstTry = true;
    while (true) {
      if (!firstTry) {
        const error = document.getElementById('ppError');
        error.textContent = '비밀 문구가 틀렸습니다. 다시 입력해주세요.';
        error.style.display = 'block';
      }
      const result = await askPassphrase(false, hint);
      const unwrapped = await unwrapKey(result.passphrase, uid);
      if (unwrapped) {
        localStorage.setItem(storageKey, unwrapped);
        const keyBytes = fromBase64(unwrapped);
        return await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt', 'decrypt']);
      }
      firstTry = false;
    }
  } else {
    // 신규 유저: 키 생성 + 비밀 문구 설정
    const result = await askPassphrase(true);
    const rawKey = crypto.getRandomValues(new Uint8Array(32));
    rawKeyB64 = toBase64(rawKey);
    localStorage.setItem(storageKey, rawKeyB64);
    await wrapAndStoreKey(rawKeyB64, result.passphrase, result.hint, uid);
    return await crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['encrypt', 'decrypt']);
  }
}

async function encryptData(plaintext, uid) {
  const key = await getCryptoKey(uid);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);
  const combined = new Uint8Array(iv.length + ciphertext.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(ciphertext), iv.length);
  return toBase64(combined);
}

async function decryptData(base64, uid) {
  const key = await getCryptoKey(uid);
  const combined = fromBase64(base64);
  const iv = combined.slice(0, 12);
  const ciphertext = combined.slice(12);
  const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  return new TextDecoder().decode(decrypted);
}

// ===== 저장/불러오기 =====
function loadNotesLocal() {
  try {
    const data = localStorage.getItem(STORAGE_KEY);
    return data ? JSON.parse(data) : [];
  } catch { return []; }
}

function saveNotesLocal(data) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
}

async function loadNotesCloud() {
  if (!currentUser) return [];
  try {
    const snap = await getDoc(doc(db, 'users', currentUser.uid));
    if (!snap.exists()) return [];
    const encrypted = snap.data().encrypted;
    if (encrypted) {
      const json = await decryptData(encrypted, currentUser.uid);
      return JSON.parse(json);
    }
    // 암호화 전 기존 데이터 호환
    return snap.data().notes || [];
  } catch (e) {
    console.error('Cloud load error:', e);
    return [];
  }
}

async function saveNotesCloud(data) {
  if (!currentUser) return;
  try {
    const json = JSON.stringify(data);
    const encrypted = await encryptData(json, currentUser.uid);
    await setDoc(doc(db, 'users', currentUser.uid), { encrypted });
  } catch (e) {
    console.error('Cloud save error:', e);
  }
}

async function loadNotes() {
  if (authMode === 'google' && currentUser) {
    return await loadNotesCloud();
  }
  return loadNotesLocal();
}

function scheduleSave() {
  clearTimeout(saveTimeout);
  saveTimeout = setTimeout(async () => {
    if (authMode === 'google' && currentUser) {
      saveNotesLocal(notes); // 로컬 백업도 유지
      await saveNotesCloud(notes);
    } else {
      saveNotesLocal(notes);
    }
  }, 300);
}

// ===== 온보딩 =====
function showOnboarding() {
  document.getElementById('onboarding').classList.remove('hidden');
}

function hideOnboarding() {
  document.getElementById('onboarding').classList.add('hidden');
}

function showLoading() {
  document.getElementById('loadingOverlay').classList.remove('hidden');
}

function hideLoading() {
  document.getElementById('loadingOverlay').classList.add('hidden');
}

// ===== 유저 UI =====
function showUserUI(user) {
  const avatar = document.getElementById('userAvatar');
  avatar.src = user.photoURL || '';
  avatar.style.display = user.photoURL ? 'block' : 'none';
  document.getElementById('userMenuName').textContent = user.displayName || user.email;
}

function hideUserUI() {
  document.getElementById('userAvatar').style.display = 'none';
  document.getElementById('userMenu').classList.remove('show');
}

// ===== 툴바 높이 동적 반영 =====
function adjustNotesAreaTop() {
  const toolbar = document.querySelector('.toolbar');
  const area = document.getElementById('notesArea');
  if (toolbar && area) {
    area.style.top = toolbar.offsetHeight + 'px';
  }
}

// ===== 스크롤 영역 업데이트 (데스크톱) =====
function updateSpacer() {
  if (isMobile) return;
  const spacer = document.getElementById('notesAreaSpacer');
  if (!spacer) return;
  let maxRight = 0;
  let maxBottom = 0;
  notes.forEach(note => {
    const right = (note.x || 0) + (note.w || 240) + 40;
    const bottom = (note.y || 0) + (note.h || 180) + 40;
    if (right > maxRight) maxRight = right;
    if (bottom > maxBottom) maxBottom = bottom;
  });
  spacer.style.width = maxRight + 'px';
  spacer.style.height = maxBottom + 'px';
}

// ===== 초기화 =====
async function init() {
  buildColorPicker();
  buildPalettePopup();
  setupEvents();
  setupPWA();
  requestAnimationFrame(adjustNotesAreaTop);
  window.addEventListener('resize', adjustNotesAreaTop);

  // 온보딩 분기
  if (authMode === 'local') {
    hideOnboarding();
    notes = loadNotesLocal();
    renderAll();
  } else if (authMode === 'google') {
    hideOnboarding();
    showLoading();
    // Firebase auth state가 결정될 때까지 기다림
    onAuthStateChanged(auth, async (user) => {
      hideLoading();
      if (user) {
        currentUser = user;
        showUserUI(user);
        notes = await loadNotesCloud();
        renderAll();
      } else {
        // 토큰 만료 등 → 온보딩으로
        authMode = null;
        localStorage.removeItem(MODE_KEY);
        showOnboarding();
      }
    });
  } else {
    // 첫 방문
    showOnboarding();
  }
}

// 온보딩 버튼
document.getElementById('obGoogle').addEventListener('click', async () => {
  showLoading();
  try {
    const result = await signInWithPopup(auth, provider);
    currentUser = result.user;
    authMode = 'google';
    localStorage.setItem(MODE_KEY, 'google');
    showUserUI(currentUser);
    hideOnboarding();

    // 로컬에 기존 메모가 있으면 클라우드로 마이그레이션
    const localNotes = loadNotesLocal();
    const cloudNotes = await loadNotesCloud();
    if (localNotes.length > 0 && cloudNotes.length === 0) {
      notes = localNotes;
      await saveNotesCloud(notes);
    } else {
      notes = cloudNotes;
    }
    renderAll();
  } catch (e) {
    console.error('Login error:', e);
    alert('로그인에 실패했습니다. 다시 시도해주세요.');
  }
  hideLoading();
});

document.getElementById('obLocal').addEventListener('click', () => {
  authMode = 'local';
  localStorage.setItem(MODE_KEY, 'local');
  hideOnboarding();
  notes = loadNotesLocal();
  renderAll();
});

// 유저 메뉴
document.getElementById('userAvatar').addEventListener('click', () => {
  document.getElementById('userMenu').classList.toggle('show');
});

document.getElementById('logoutBtn').addEventListener('click', async () => {
  await signOut(auth);
  currentUser = null;
  authMode = null;
  localStorage.removeItem(MODE_KEY);
  hideUserUI();
  notes = [];
  renderAll();
  showOnboarding();
});

document.addEventListener('click', e => {
  if (!e.target.closest('#userAvatar') && !e.target.closest('#userMenu')) {
    document.getElementById('userMenu').classList.remove('show');
  }
});

// ===== UI 빌드 =====
function buildColorPicker() {
  const cp = document.getElementById('colorPicker');
  COLORS.forEach(c => {
    const dot = document.createElement('div');
    dot.className = 'color-dot' + (c.hex === selectedColor ? ' active' : '');
    dot.style.background = c.hex;
    dot.title = c.name;
    dot.addEventListener('click', () => {
      selectedColor = c.hex;
      cp.querySelectorAll('.color-dot').forEach(d => d.classList.remove('active'));
      dot.classList.add('active');
    });
    cp.appendChild(dot);
  });
}

function buildPalettePopup() {
  const pp = document.getElementById('palettePopup');
  COLORS.forEach(c => {
    const dot = document.createElement('div');
    dot.className = 'palette-dot';
    dot.style.background = c.hex;
    dot.dataset.color = c.hex;
    pp.appendChild(dot);
  });
}

function renderAll() {
  const area = document.getElementById('notesArea');
  area.querySelectorAll('.note').forEach(n => n.remove());
  notes.forEach(note => { if (note.y < 0) note.y = 0; });
  notes.forEach((note, i) => area.appendChild(createNoteEl(note, i)));
  updateEmpty();
  updateSpacer();
}

function updateEmpty() {
  document.getElementById('emptyState').style.display = notes.length === 0 ? 'block' : 'none';
}

function createNoteEl(note, idx) {
  const el = document.createElement('div');
  const isTodo = note.mode === 'todo';
  el.className = 'note' + (isTodo ? ' note-todo' : '');
  el.dataset.idx = idx;
  if (!isMobile) {
    el.style.left = note.x + 'px';
    el.style.top = note.y + 'px';
    el.style.width = (note.w || 240) + 'px';
    el.style.minHeight = (note.h || 180) + 'px';
  }
  el.style.background = note.color;
  el.style.zIndex = note.z || nextZ++;

  const ts = new Date(note.created).toLocaleDateString('ko-KR', {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'
  });

  const items = note.items || [];
  const total = items.length;
  const done = items.filter(it => it.done).length;
  const pct = total > 0 ? Math.round((done / total) * 100) : 0;

  const progressHtml = isTodo
    ? `<span class="note-progress">${done}/${total} · ${pct}%</span>`
    : '';
  const strikeBtn = isTodo
    ? ''
    : `<button class="note-btn note-strike-btn" title="취소선">S̶</button>`;
  const todoBtnTitle = isTodo ? '일반 메모로' : '할 일 모드';

  const bodyHtml = isTodo
    ? renderTodoBody(items)
    : `<div class="note-body" contenteditable="true" data-field="body">${note.body || ''}</div>`;

  el.innerHTML = `
    <div class="note-header">
      <input class="note-title-input" value="${escHtml(note.title || '')}" placeholder="제목..." data-field="title">
      ${progressHtml}
      <button class="note-btn note-todo-btn${isTodo ? ' active' : ''}" title="${todoBtnTitle}">✓</button>
      ${strikeBtn}
      <button class="note-btn note-palette-btn" title="색상 변경">🎨</button>
      <button class="note-btn note-dup-btn" title="복제">📋</button>
      <button class="note-btn note-del-btn" title="삭제">✕</button>
    </div>
    ${bodyHtml}
    <div class="note-footer">${ts}</div>
    <div class="note-resize"></div>
  `;
  return el;
}

function renderTodoBody(items) {
  const rows = items.map((it, i) => `
    <div class="todo-item${it.done ? ' done' : ''}" data-todo-idx="${i}">
      <input type="checkbox" class="todo-checkbox"${it.done ? ' checked' : ''}>
      <input type="text" class="todo-text" value="${escHtml(it.text || '')}" placeholder="할 일...">
      <button class="todo-del" title="항목 삭제">✕</button>
    </div>
  `).join('');
  return `
    <div class="note-body note-body-todo">
      ${rows}
      <button class="todo-add">+ 항목 추가</button>
    </div>
  `;
}

function stripHtmlToText(html) {
  const d = document.createElement('div');
  d.innerHTML = (html || '')
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/(div|p)>/gi, '\n');
  return d.textContent || '';
}

function escHtml(s) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function getPointerPos(e) {
  if (e.touches && e.touches.length > 0) return { x: e.touches[0].clientX, y: e.touches[0].clientY };
  if (e.changedTouches && e.changedTouches.length > 0) return { x: e.changedTouches[0].clientX, y: e.changedTouches[0].clientY };
  return { x: e.clientX, y: e.clientY };
}

// ===== 이벤트 =====
function setupEvents() {
  const area = document.getElementById('notesArea');

  document.getElementById('addBtn').addEventListener('click', addNote);
  document.getElementById('undoBtn').addEventListener('click', doUndo);
  document.getElementById('redoBtn').addEventListener('click', doRedo);
  document.getElementById('refreshBtn').addEventListener('click', async () => {
    pushUndo();
    notes = await loadNotes();
    renderAll();
  });

  const searchBox = document.getElementById('searchBox');
  const clearBtn = document.getElementById('clearSearchBtn');
  searchBox.addEventListener('input', () => {
    const q = searchBox.value.toLowerCase();
    clearBtn.style.display = q ? 'inline-block' : 'none';
    area.querySelectorAll('.note').forEach(el => {
      const idx = +el.dataset.idx;
      const note = notes[idx];
      const itemsText = (note.items || []).map(it => it.text).join(' ');
      const haystack = (note.title + ' ' + (note.body || '') + ' ' + itemsText).toLowerCase();
      const match = !q || haystack.includes(q);
      el.classList.toggle('hidden-note', !match);
    });
  });
  clearBtn.addEventListener('click', () => {
    searchBox.value = '';
    clearBtn.style.display = 'none';
    area.querySelectorAll('.note').forEach(el => el.classList.remove('hidden-note'));
  });

  function onPointerDown(e) {
    const noteEl = e.target.closest('.note');
    if (!noteEl) return;
    const idx = +noteEl.dataset.idx;

    if (e.target.closest('.note-del-btn')) {
      e.stopPropagation();
      const title = notes[idx].title || '제목 없음';
      if (!confirm(`"${title}" 메모를 삭제하시겠습니까?`)) return;
      pushUndo();
      notes.splice(idx, 1);
      renderAll();
      scheduleSave();
      return;
    }
    if (e.target.closest('.note-dup-btn')) { duplicateNote(idx); return; }
    if (e.target.closest('.note-strike-btn')) { toggleStrikethrough(noteEl, idx); return; }
    if (e.target.closest('.note-palette-btn')) { showPalette(noteEl, idx); return; }
    if (e.target.closest('.note-todo-btn')) { e.stopPropagation(); toggleTodoMode(noteEl, idx); return; }
    if (e.target.closest('.todo-add')) { e.stopPropagation(); addTodoItem(noteEl, idx); return; }
    const todoDelEl = e.target.closest('.todo-del');
    if (todoDelEl) {
      e.stopPropagation();
      const itemIdx = +todoDelEl.closest('.todo-item').dataset.todoIdx;
      removeTodoItem(noteEl, idx, itemIdx);
      return;
    }
    if (e.target.closest('.todo-checkbox') || e.target.closest('.todo-text')) {
      // 체크박스/입력은 기본 동작 유지, 드래그 방지
      return;
    }

    if (!isMobile) {
      const pos = getPointerPos(e);
      if (e.target.closest('.note-resize')) {
        resizeState = { el: noteEl, idx, startX: pos.x, startY: pos.y,
          startW: noteEl.offsetWidth, startH: noteEl.offsetHeight };
        e.preventDefault();
        return;
      }
      if (e.target.closest('.note-header') && !e.target.closest('input')) {
        noteEl.style.zIndex = ++nextZ;
        notes[idx].z = nextZ;
        dragState = { el: noteEl, idx, offX: pos.x - noteEl.offsetLeft, offY: pos.y - noteEl.offsetTop };
        noteEl.classList.add('dragging');
        e.preventDefault();
        return;
      }
      noteEl.style.zIndex = ++nextZ;
      notes[idx].z = nextZ;
    }
  }

  function onPointerMove(e) {
    if (dragState) {
      const pos = getPointerPos(e);
      const area = document.getElementById('notesArea');
      const newX = pos.x - dragState.offX;
      const newY = Math.max(0, pos.y - dragState.offY);
      dragState.el.style.left = newX + 'px';
      dragState.el.style.top = newY + 'px';
      notes[dragState.idx].x = newX;
      notes[dragState.idx].y = newY;
    }
    if (resizeState) {
      const pos = getPointerPos(e);
      const w = Math.max(180, resizeState.startW + (pos.x - resizeState.startX));
      const h = Math.max(120, resizeState.startH + (pos.y - resizeState.startY));
      resizeState.el.style.width = w + 'px';
      resizeState.el.style.minHeight = h + 'px';
      notes[resizeState.idx].w = w;
      notes[resizeState.idx].h = h;
    }
  }

  function onPointerUp() {
    if (dragState) { pushUndo(); dragState.el.classList.remove('dragging'); dragState = null; scheduleSave(); updateSpacer(); }
    if (resizeState) { pushUndo(); resizeState = null; scheduleSave(); updateSpacer(); }
  }

  area.addEventListener('mousedown', onPointerDown);
  document.addEventListener('mousemove', onPointerMove);
  document.addEventListener('mouseup', onPointerUp);
  area.addEventListener('touchstart', onPointerDown, { passive: false });
  document.addEventListener('touchmove', onPointerMove, { passive: false });
  document.addEventListener('touchend', onPointerUp);

  area.addEventListener('input', e => {
    const noteEl = e.target.closest('.note');
    if (!noteEl) return;
    const idx = +noteEl.dataset.idx;
    // 텍스트 입력은 디바운스로 Undo 스냅샷 (타이핑 멈춘 후 1초)
    clearTimeout(inputSnapshotTimer);
    inputSnapshotTimer = setTimeout(() => pushUndo(), 1000);
    if (e.target.dataset.field === 'title') notes[idx].title = e.target.value;
    else if (e.target.dataset.field === 'body') notes[idx].body = e.target.innerHTML;
    else if (e.target.classList.contains('todo-text')) {
      const itemEl = e.target.closest('.todo-item');
      if (itemEl && notes[idx].items) {
        const itemIdx = +itemEl.dataset.todoIdx;
        notes[idx].items[itemIdx].text = e.target.value;
      }
    }
    scheduleSave();
  });

  area.addEventListener('change', e => {
    if (!e.target.classList.contains('todo-checkbox')) return;
    const noteEl = e.target.closest('.note');
    if (!noteEl) return;
    const idx = +noteEl.dataset.idx;
    const itemEl = e.target.closest('.todo-item');
    if (!itemEl || !notes[idx].items) return;
    const itemIdx = +itemEl.dataset.todoIdx;
    pushUndo();
    notes[idx].items[itemIdx].done = e.target.checked;
    itemEl.classList.toggle('done', e.target.checked);
    updateTodoProgress(noteEl, notes[idx]);
    scheduleSave();
  });

  area.addEventListener('keydown', e => {
    if (!e.target.classList.contains('todo-text')) return;
    const noteEl = e.target.closest('.note');
    if (!noteEl) return;
    const idx = +noteEl.dataset.idx;
    const itemEl = e.target.closest('.todo-item');
    if (!itemEl) return;
    const itemIdx = +itemEl.dataset.todoIdx;
    if (e.key === 'Enter') {
      e.preventDefault();
      addTodoItem(noteEl, idx, itemIdx);
    } else if (e.key === 'Backspace' && e.target.value === '' && (notes[idx].items || []).length > 1) {
      e.preventDefault();
      removeTodoItem(noteEl, idx, itemIdx, Math.max(0, itemIdx - 1));
    }
  });

  document.addEventListener('click', e => {
    if (!e.target.closest('.palette-popup') && !e.target.closest('.note-palette-btn')) {
      document.getElementById('palettePopup').classList.remove('show');
    }
  });

  document.addEventListener('keydown', e => {
    if (e.ctrlKey && e.key === 'n') { e.preventDefault(); addNote(); }
    if (e.ctrlKey && e.key === 'z' && !e.shiftKey) { e.preventDefault(); doUndo(); }
    if (e.ctrlKey && (e.key === 'y' || (e.key === 'z' && e.shiftKey))) { e.preventDefault(); doRedo(); }
  });
}

function addNote() {
  pushUndo();
  const area = document.getElementById('notesArea');
  const x = 40 + (notes.length % 6) * 30;
  const y = 20 + (notes.length % 5) * 30;
  const note = {
    title: '', body: '', color: selectedColor,
    x, y, w: 240, h: 180, z: ++nextZ,
    created: new Date().toISOString(),
  };
  notes.push(note);
  const el = createNoteEl(note, notes.length - 1);
  area.appendChild(el);
  el.querySelector('.note-body').focus();
  updateEmpty();
  updateSpacer();
  scheduleSave();
}

function duplicateNote(idx) {
  pushUndo();
  const src = notes[idx];
  const note = { ...src, x: src.x + 20, y: src.y + 20, z: ++nextZ, created: new Date().toISOString() };
  notes.push(note);
  document.getElementById('notesArea').appendChild(createNoteEl(note, notes.length - 1));
  updateSpacer();
  scheduleSave();
}

function toggleTodoMode(noteEl, idx) {
  pushUndo();
  const note = notes[idx];
  if (note.mode === 'todo') {
    const lines = (note.items || [])
      .filter(it => (it.text || '').trim())
      .map(it => it.done ? `<s>${escHtml(it.text)}</s>` : escHtml(it.text));
    note.body = lines.join('<br>');
    note.mode = 'note';
    delete note.items;
  } else {
    const text = stripHtmlToText(note.body);
    const lines = text.split('\n').map(s => s.trim()).filter(Boolean);
    note.items = lines.length > 0
      ? lines.map(t => ({ text: t, done: false }))
      : [{ text: '', done: false }];
    note.mode = 'todo';
    note.body = '';
  }
  const newEl = createNoteEl(note, idx);
  noteEl.replaceWith(newEl);
  if (note.mode === 'todo') {
    const first = newEl.querySelector('.todo-text');
    if (first) first.focus();
  }
  scheduleSave();
}

function addTodoItem(noteEl, idx, afterIdx = -1) {
  pushUndo();
  const note = notes[idx];
  if (!note.items) note.items = [];
  const newItem = { text: '', done: false };
  const insertAt = afterIdx >= 0 ? afterIdx + 1 : note.items.length;
  note.items.splice(insertAt, 0, newItem);
  const newEl = createNoteEl(note, idx);
  noteEl.replaceWith(newEl);
  const inputs = newEl.querySelectorAll('.todo-text');
  if (inputs[insertAt]) inputs[insertAt].focus();
  scheduleSave();
}

function removeTodoItem(noteEl, idx, itemIdx, focusItemIdx = null) {
  pushUndo();
  const note = notes[idx];
  if (!note.items) return;
  note.items.splice(itemIdx, 1);
  const newEl = createNoteEl(note, idx);
  noteEl.replaceWith(newEl);
  if (focusItemIdx !== null) {
    const inputs = newEl.querySelectorAll('.todo-text');
    const target = inputs[Math.min(focusItemIdx, inputs.length - 1)];
    if (target) {
      target.focus();
      target.setSelectionRange(target.value.length, target.value.length);
    }
  }
  scheduleSave();
}

function updateTodoProgress(noteEl, note) {
  const total = (note.items || []).length;
  const done = (note.items || []).filter(it => it.done).length;
  const pct = total > 0 ? Math.round((done / total) * 100) : 0;
  const prog = noteEl.querySelector('.note-progress');
  if (prog) prog.textContent = `${done}/${total} · ${pct}%`;
}

function toggleStrikethrough(noteEl, idx) {
  const body = noteEl.querySelector('.note-body');
  const sel = window.getSelection();
  if (!sel.rangeCount || sel.isCollapsed || !body.contains(sel.anchorNode)) return;
  pushUndo();
  document.execCommand('strikeThrough', false, null);
  notes[idx].body = body.innerHTML;
  scheduleSave();
}

function showPalette(noteEl, idx) {
  const pp = document.getElementById('palettePopup');
  const rect = noteEl.querySelector('.note-palette-btn').getBoundingClientRect();
  pp.style.left = Math.min(rect.left, window.innerWidth - 140) + 'px';
  pp.style.top = (rect.bottom + 4) + 'px';
  pp.classList.add('show');
  pp.onclick = e => {
    const dot = e.target.closest('.palette-dot');
    if (!dot) return;
    pushUndo();
    notes[idx].color = dot.dataset.color;
    noteEl.style.background = dot.dataset.color;
    pp.classList.remove('show');
    scheduleSave();
  };
}

function reindex() {
  document.getElementById('notesArea').querySelectorAll('.note').forEach((el, i) => el.dataset.idx = i);
}

// ===== PWA =====
let deferredPrompt = null;
function setupPWA() {
  window.addEventListener('beforeinstallprompt', e => {
    e.preventDefault();
    deferredPrompt = e;
    document.getElementById('installBanner').classList.add('show');
  });
  document.getElementById('installBtn').addEventListener('click', async () => {
    if (!deferredPrompt) return;
    deferredPrompt.prompt();
    await deferredPrompt.userChoice;
    deferredPrompt = null;
    document.getElementById('installBanner').classList.remove('show');
  });
  document.getElementById('installDismiss').addEventListener('click', () => {
    document.getElementById('installBanner').classList.remove('show');
  });
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('sw.js').then(reg => {
      // 한 시간마다 새 버전 체크
      setInterval(() => reg.update().catch(() => {}), 60 * 60 * 1000);
      // 페이지 보일 때마다 한 번 체크 (PWA 재진입 시)
      document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'visible') reg.update().catch(() => {});
      });
    }).catch(() => {});

    // 새 SW가 활성화되면 자동 새로고침 (첫 설치는 제외)
    let hadController = !!navigator.serviceWorker.controller;
    let refreshing = false;
    navigator.serviceWorker.addEventListener('controllerchange', () => {
      if (!hadController) { hadController = true; return; }
      if (refreshing) return;
      refreshing = true;
      // 진행 중인 저장이 끝날 시간을 살짝 줌
      setTimeout(() => window.location.reload(), 400);
    });
  }
}

init();
