/**
 * script.js — VDEX Analyzer browser demo
 *
 * Bridges the FileReader API with the Go/WASM vdex engine.
 * API surface exposed by wasm/main.go:
 *   window.vdex.explain(Uint8Array) → { fields, total_bytes, unmapped_gaps } | { error }
 *   window.vdex.parse(Uint8Array)   → VdexReport | { error }
 *   window.vdex.version             → string
 */

'use strict';

/* ── State ─────────────────────────────────────────────────── */
let wasmReady = false;
let currentFieldMap = null;   // raw object from window.vdex.explain
let currentReport   = null;   // raw object from window.vdex.parse
let currentBytes    = null;   // Uint8Array of the loaded file
let activeTab       = 'explain';

/* ── DOM refs ────────────────────────────────────────────────── */
const q = id => document.getElementById(id);

const $wasmStatus    = q('wasm-status');
const $dropZone      = q('drop-zone');
const $fileInput     = q('file-input');
const $filePickerBtn = q('file-picker-btn');
const $fileInfoBar   = q('file-info-bar');
const $fileNameLabel = q('file-name-label');
const $fileSizeLabel = q('file-size-label');
const $resetBtn      = q('reset-btn');
const $spinner       = q('analyze-spinner');
const $panelExplain  = q('panel-explain');
const $panelParse    = q('panel-parse');
const $errorBanner   = q('error-banner');
const $errorMessage  = q('error-message');
const $sectionFilter = q('section-filter');
const $typeFilter    = q('type-filter');
const $hidePadding   = q('hide-padding');
const $copyJsonBtn   = q('copy-json-btn');
const $fieldTbody    = q('field-tbody');
const $rowCount      = q('row-count');
const $coverageFill  = q('coverage-fill');
const $coveragePct   = q('coverage-pct');
const $statTotal     = q('stat-total');
const $statFields    = q('stat-fields');
const $statGaps      = q('stat-gaps');
const $parseGrid     = q('parse-grid');
const $tabExplain    = q('tab-explain');
const $tabParse      = q('tab-parse');
const $hexModal      = q('hex-modal');
const $modalTitle    = q('modal-title');
const $modalBody     = q('modal-body');
const $modalClose    = q('modal-close');

/* ── WASM bootstrap ─────────────────────────────────────────── */
async function loadWasm() {
  setWasmStatus('loading', 'Loading WASM engine…');
  try {
    const go = new Go();
    // vdex.wasm lives next to index.html (built by Makefile)
    const result = await WebAssembly.instantiateStreaming(
      fetch('vdex.wasm'),
      go.importObject
    );
    go.run(result.instance);
    // give the Go runtime a tick to register window.vdex
    await new Promise(r => setTimeout(r, 100));
    if (typeof window.vdex === 'undefined') {
      throw new Error('window.vdex not found after WASM init');
    }
    wasmReady = true;
    const ver = window.vdex.version || '';
    setWasmStatus('ready', `Engine ready${ver ? ' · ' + ver : ''}`);
  } catch (err) {
    setWasmStatus('error', 'Failed to load engine: ' + err.message);
    console.error('[vdex wasm]', err);
  }
}

function setWasmStatus(state, text) {
  const dot = $wasmStatus.querySelector('.badge-dot');
  const label = $wasmStatus.querySelector('.badge-text');
  dot.className = 'badge-dot ' + state;
  label.textContent = text;
}

/* ── Drop / file handling ────────────────────────────────────── */
$dropZone.addEventListener('dragover', e => {
  e.preventDefault();
  $dropZone.classList.add('drag-over');
});

$dropZone.addEventListener('dragleave', () => {
  $dropZone.classList.remove('drag-over');
});

$dropZone.addEventListener('drop', e => {
  e.preventDefault();
  $dropZone.classList.remove('drag-over');
  const file = e.dataTransfer.files[0];
  if (file) processFile(file);
});

$dropZone.addEventListener('click', () => $fileInput.click());
$dropZone.addEventListener('keydown', e => {
  if (e.key === 'Enter' || e.key === ' ') $fileInput.click();
});

$filePickerBtn.addEventListener('click', e => {
  e.stopPropagation();
  $fileInput.click();
});

$fileInput.addEventListener('change', () => {
  const file = $fileInput.files[0];
  if (file) processFile(file);
});

$resetBtn.addEventListener('click', resetUI);

/* ── Tab switching ───────────────────────────────────────────── */
$tabExplain.addEventListener('click', () => switchTab('explain'));
$tabParse.addEventListener('click',   () => switchTab('parse'));

function switchTab(tab) {
  activeTab = tab;
  $tabExplain.classList.toggle('active', tab === 'explain');
  $tabParse.classList.toggle('active',   tab === 'parse');
  $panelExplain.classList.toggle('hidden', tab !== 'explain');
  $panelParse.classList.toggle('hidden',   tab !== 'parse');
}

/* ── Filter handling ─────────────────────────────────────────── */
$sectionFilter.addEventListener('input', applyFilters);
$typeFilter.addEventListener('change', applyFilters);
$hidePadding.addEventListener('change', applyFilters);

/* ── Copy JSON ───────────────────────────────────────────────── */
$copyJsonBtn.addEventListener('click', () => {
  if (!currentFieldMap) return;
  navigator.clipboard.writeText(JSON.stringify(currentFieldMap, null, 2)).then(() => {
    const orig = $copyJsonBtn.textContent;
    $copyJsonBtn.textContent = '✓ Copied!';
    setTimeout(() => { $copyJsonBtn.textContent = orig; }, 2000);
  });
});

/* ── Modal ───────────────────────────────────────────────────── */
$modalClose.addEventListener('click', closeModal);
$hexModal.addEventListener('click', e => { if (e.target === $hexModal) closeModal(); });
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });

function closeModal() { $hexModal.classList.add('hidden'); }

/* ── File processing ─────────────────────────────────────────── */
async function processFile(file) {
  if (!wasmReady) {
    showError('WASM engine is not ready yet. Please wait a moment and try again.');
    return;
  }

  resetResult();
  $dropZone.classList.add('hidden');
  $fileInfoBar.classList.remove('hidden');
  $fileNameLabel.textContent = file.name;
  $fileSizeLabel.textContent = formatBytes(file.size);
  $spinner.classList.remove('hidden');
  hideError();

  try {
    const buffer = await file.arrayBuffer();
    currentBytes = new Uint8Array(buffer);

    // Run both explain and parse in parallel
    const [explainResult, parseResult] = await Promise.all([
      runExplain(currentBytes),
      runParse(currentBytes),
    ]);

    if (explainResult.error) throw new Error(explainResult.error);
    currentFieldMap = explainResult;
    currentReport   = parseResult;

    renderExplain(currentFieldMap);
    renderParse(currentReport);

    $spinner.classList.add('hidden');
    switchTab('explain');
    $panelExplain.classList.remove('hidden');
    $panelParse.classList.add('hidden');
  } catch (err) {
    $spinner.classList.add('hidden');
    showError(err.message);
    console.error('[vdex demo]', err);
  }
}

function runExplain(bytes) {
  return new Promise(resolve => {
    // WASM calls are synchronous; wrap to avoid blocking the event loop briefly
    setTimeout(() => {
      try {
        const result = window.vdex.explain(bytes);
        resolve(result);
      } catch (e) {
        resolve({ error: e.message });
      }
    }, 0);
  });
}

function runParse(bytes) {
  return new Promise(resolve => {
    setTimeout(() => {
      try {
        const result = window.vdex.parse(bytes);
        resolve(result);
      } catch (e) {
        resolve({ error: e.message });
      }
    }, 0);
  });
}

/* ── Explain renderer ────────────────────────────────────────── */
function renderExplain(fm) {
  const total    = fm.total_bytes || 0;
  const fields   = fm.fields || [];
  const gaps     = fm.unmapped_gaps || [];

  // Coverage: bytes covered by non-padding fields
  let covered = 0;
  for (const f of fields) {
    if (f.type !== 'padding') covered += (f.size || 0);
  }
  const pct = total > 0 ? Math.round(covered / total * 10000) / 100 : 0;

  $coverageFill.style.width = pct + '%';
  $coveragePct.textContent  = pct + '%';
  $statTotal.textContent    = total.toLocaleString();
  $statFields.textContent   = fields.length.toLocaleString();
  $statGaps.textContent     = gaps.length.toLocaleString();

  applyFilters();
}

function applyFilters() {
  if (!currentFieldMap) return;
  const fields      = currentFieldMap.fields || [];
  const pathFilter  = ($sectionFilter.value || '').toLowerCase();
  const typeFilter  = ($typeFilter.value || '').toLowerCase();
  const hidePad     = $hidePadding.checked;

  const visible = fields.filter(f => {
    if (hidePad && f.type === 'padding') return false;
    if (typeFilter && !f.type.includes(typeFilter)) return false;
    if (pathFilter && !(f.logical_path || '').toLowerCase().includes(pathFilter)) return false;
    return true;
  });

  renderFieldRows(visible);
  $rowCount.textContent = `Showing ${visible.length.toLocaleString()} of ${fields.length.toLocaleString()} fields`;
}

function renderFieldRows(fields) {
  $fieldTbody.innerHTML = '';
  const fragment = document.createDocumentFragment();

  for (const f of fields) {
    const tr = document.createElement('tr');
    tr.dataset.field = JSON.stringify(f);
    tr.addEventListener('click', () => openModal(f));

    tr.appendChild(cell($, f.offset != null ? '0x' + f.offset.toString(16).toUpperCase().padStart(8, '0') : '—', 'offset-cell mono'));
    tr.appendChild(cell($, f.size != null ? f.size.toString() : '—', 'mono'));
    tr.appendChild(typeBadgeCell(f.type));
    tr.appendChild(cell($, f.logical_path || '—', 'path-cell'));
    tr.appendChild(cell($, formatValue(f), 'value-cell'));
    tr.appendChild(cell($, formatHex(f.raw_bytes), 'hex-cell'));
    tr.appendChild(cell($, f.description || f.summary || '—', 'desc-cell'));

    fragment.appendChild(tr);
  }

  $fieldTbody.appendChild(fragment);
}

function cell($, text, className) {
  const td = document.createElement('td');
  td.textContent = text;
  if (className) td.className = className;
  return td;
}

function typeBadgeCell(type) {
  const td = document.createElement('td');
  const span = document.createElement('span');
  span.className = 'type-badge ' + typeClass(type);
  span.textContent = type || '—';
  td.appendChild(span);
  return td;
}

function typeClass(t) {
  if (!t) return '';
  if (t === 'magic')     return 'type-magic';
  if (t === 'uint8')     return 'type-uint8';
  if (t === 'uint16_le') return 'type-uint16';
  if (t === 'uint32_le') return 'type-uint32';
  if (t === 'uint64_le') return 'type-uint64';
  if (t === 'uleb128')   return 'type-uleb128';
  if (t === 'bytes')     return 'type-bytes';
  if (t === 'padding')   return 'type-padding';
  if (t === 'cstring')   return 'type-cstring';
  return '';
}

function formatValue(f) {
  const v = f.parsed_value;
  if (v == null) return '—';
  if (typeof v === 'string') {
    // truncate long strings
    return v.length > 48 ? v.slice(0, 48) + '…' : v;
  }
  if (typeof v === 'number') {
    // show hex for offsets and large numbers
    if (f.type === 'uint32_le' || f.type === 'uint64_le') {
      return v.toString() + ' (0x' + v.toString(16).toUpperCase() + ')';
    }
    return v.toString();
  }
  if (Array.isArray(v)) return '[' + v.length + ' bytes]';
  return String(v);
}

function formatHex(raw) {
  if (!raw || raw.length === 0) return '—';
  const slice = raw.slice(0, 14);
  const hex = Array.from(slice).map(b => b.toString(16).padStart(2, '0')).join(' ');
  return raw.length > 14 ? hex + '…' : hex;
}

/* ── Field detail modal ──────────────────────────────────────── */
function openModal(f) {
  $modalTitle.textContent = f.logical_path || 'Field Detail';

  const rows = [
    ['Offset',       f.offset != null ? '0x' + f.offset.toString(16).toUpperCase() + ' (' + f.offset + ')' : '—'],
    ['Size',         f.size != null ? f.size + ' byte' + (f.size !== 1 ? 's' : '') : '—'],
    ['Type',         f.type || '—'],
    ['Logical path', f.logical_path || '—'],
    ['Summary',      f.summary || '—'],
    ['Description',  f.description || '—'],
    ['Parsed value', formatFullValue(f.parsed_value)],
  ];

  let html = rows.map(([k, v]) =>
    `<div class="modal-field">
      <span class="modal-label">${escHtml(k)}</span>
      <span class="modal-value">${escHtml(String(v))}</span>
    </div>`
  ).join('');

  // Full hex dump
  if (f.raw_bytes && f.raw_bytes.length > 0) {
    const hexFull = Array.from(f.raw_bytes)
      .map(b => b.toString(16).padStart(2, '0').toUpperCase())
      .join(' ');
    html += `<div class="hex-dump">${escHtml(hexFull)}</div>`;
  }

  $modalBody.innerHTML = html;
  $hexModal.classList.remove('hidden');
}

function formatFullValue(v) {
  if (v == null) return '—';
  if (typeof v === 'string') return v;
  if (Array.isArray(v)) return v.map(b => b.toString(16).padStart(2, '0')).join(' ');
  return String(v);
}

/* ── Parse renderer ──────────────────────────────────────────── */
function renderParse(report) {
  if (!report || report.error) return;

  const cards = [];

  // Header card
  if (report.header) {
    const h = report.header;
    cards.push({
      title: 'VDEX Header',
      rows: [
        ['Magic',        bytesToStr(h.magic)],
        ['Version',      h.version != null ? h.version : '—'],
        ['DEX count',    h.dex_count != null ? h.dex_count : '—'],
        ['DEX size',     h.dex_size != null ? h.dex_size + ' bytes' : '—'],
        ['VerDeps size', h.verifier_deps_size != null ? h.verifier_deps_size + ' bytes' : '—'],
        ['TypeLookup size', h.type_lookup_table_size != null ? h.type_lookup_table_size + ' bytes' : '—'],
      ],
    });
  }

  // Coverage card
  if (report.coverage) {
    const c = report.coverage;
    const sections = [];
    for (const [k, v] of Object.entries(c)) {
      if (typeof v === 'object' && v.bytes != null) {
        sections.push([k, formatBytes(v.bytes) + (v.pct != null ? ' (' + v.pct.toFixed(1) + '%)' : '')]);
      }
    }
    if (sections.length > 0) {
      cards.push({ title: 'Section Coverage', rows: sections });
    }
  }

  // DEX files card
  if (report.dex_files && report.dex_files.length > 0) {
    const rows = report.dex_files.map((d, i) => [
      'DEX ' + i,
      (d.class_count != null ? d.class_count + ' classes · ' : '') +
      (d.size != null ? formatBytes(d.size) : '—'),
    ]);
    cards.push({ title: 'DEX Payloads (' + report.dex_files.length + ')', rows });
  }

  // Checksums card
  if (report.checksums && report.checksums.length > 0) {
    const rows = report.checksums.map((c, i) => [
      'DEX ' + i, '0x' + (c >>> 0).toString(16).toUpperCase().padStart(8, '0'),
    ]);
    cards.push({ title: 'DEX Checksums', rows });
  }

  // VerifierDeps card
  if (report.verifier_deps) {
    const vd = report.verifier_deps;
    const rows = [];
    if (vd.dex_count != null)    rows.push(['DEX count',    vd.dex_count]);
    if (vd.class_count != null)  rows.push(['Classes',      vd.class_count]);
    if (vd.method_count != null) rows.push(['Methods',      vd.method_count]);
    if (vd.field_count != null)  rows.push(['Fields',       vd.field_count]);
    if (rows.length > 0) cards.push({ title: 'VerifierDeps', rows });
  }

  // Diagnostics
  if (report.diagnostics && report.diagnostics.length > 0) {
    const rows = report.diagnostics.map(d => [d.level || 'info', d.message || '—']);
    cards.push({ title: 'Diagnostics', rows });
  }

  $parseGrid.innerHTML = cards.map(c => renderCard(c)).join('');
}

function renderCard({ title, rows }) {
  const rowsHtml = rows.map(([k, v]) =>
    `<div class="parse-row">
      <span class="parse-key">${escHtml(String(k))}</span>
      <span class="parse-val">${escHtml(String(v))}</span>
    </div>`
  ).join('');
  return `
    <div class="parse-card">
      <div class="parse-card-title">${escHtml(title)}</div>
      ${rowsHtml}
    </div>`;
}

/* ── UI helpers ──────────────────────────────────────────────── */
function resetUI() {
  currentFieldMap = null;
  currentReport   = null;
  currentBytes    = null;
  $fileInput.value = '';
  $dropZone.classList.remove('hidden');
  $fileInfoBar.classList.add('hidden');
  $spinner.classList.add('hidden');
  $panelExplain.classList.add('hidden');
  $panelParse.classList.add('hidden');
  hideError();
  $fieldTbody.innerHTML = '';
  $parseGrid.innerHTML  = '';
  $sectionFilter.value  = '';
  $typeFilter.value     = '';
}

function resetResult() {
  $panelExplain.classList.add('hidden');
  $panelParse.classList.add('hidden');
  hideError();
}

function showError(msg) {
  $errorMessage.textContent = msg;
  $errorBanner.classList.remove('hidden');
}

function hideError() {
  $errorBanner.classList.add('hidden');
}

function formatBytes(n) {
  if (n == null) return '—';
  if (n < 1024) return n + ' B';
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
  return (n / 1024 / 1024).toFixed(2) + ' MB';
}

function bytesToStr(arr) {
  if (!arr) return '—';
  return Array.from(arr)
    .map(b => b >= 32 && b < 127 ? String.fromCharCode(b) : '\\x' + b.toString(16).padStart(2, '0'))
    .join('');
}

function escHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/* ── Init ─────────────────────────────────────────────────────── */
loadWasm();
