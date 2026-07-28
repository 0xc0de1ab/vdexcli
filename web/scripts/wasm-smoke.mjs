import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const [wasmArgument, runtimeArgument] = process.argv.slice(2);
if (!wasmArgument || !runtimeArgument) {
  console.error('usage: node scripts/wasm-smoke.mjs <vdex.wasm> <wasm_exec.js>');
  process.exit(2);
}

const buildMinimalVdex = () => {
  const data = new Uint8Array(68);
  const view = new DataView(data.buffer);
  data.set(new TextEncoder().encode('vdex027\0'));
  view.setUint32(8, 4, true);

  const sections = [
    [0, 60, 4],
    [1, 0, 0],
    [2, 64, 0],
    [3, 64, 0],
  ];
  sections.forEach((section, index) => {
    const offset = 12 + index * 12;
    section.forEach((value, field) => view.setUint32(offset + field * 4, value, true));
  });
  view.setUint32(60, 0xcafebabe, true);
  return data;
};

try {
  globalThis.window = globalThis;
  await import(pathToFileURL(resolve(runtimeArgument)).href);

  const go = new globalThis.Go();
  const bytes = await readFile(resolve(wasmArgument));
  const { instance } = await WebAssembly.instantiate(bytes, go.importObject);
  void go.run(instance);
  await new Promise((resolveReady) => setTimeout(resolveReady, 20));

  const input = buildMinimalVdex();
  const result = globalThis.vdex?.explain(input);
  if (!result || result.error) throw new Error(result?.error ?? 'WASM API returned no result');
  if (!Array.isArray(result.fields)) throw new Error('fields must be an array');
  if (!Array.isArray(result.unmapped_gaps)) throw new Error('unmapped_gaps must be an array');
  if (!Array.isArray(result.dex_previews)) throw new Error('dex_previews must be an array');
  if (result.dex_previews.length !== 1) throw new Error(`unexpected dex preview count: ${result.dex_previews.length}`);
  if (result.dex_previews[0].location_checksum !== 0xcafebabe) throw new Error('DEX location checksum preview mismatch');
  if (result.dex_previews[0].embedded !== false) throw new Error('checksum-only DEX preview must not be embedded');
  if (result.total_bytes !== 68) throw new Error(`unexpected total_bytes: ${result.total_bytes}`);

  const structure = globalThis.vdex?.explainStructure(input);
  if (!structure || structure.error) {
    throw new Error(structure?.error ?? 'compact WASM API returned no result');
  }
  if (!Array.isArray(structure.fields)) throw new Error('compact fields must be an array');
  if (!Array.isArray(structure.unmapped_gaps)) throw new Error('compact unmapped_gaps must be an array');
  if (!Array.isArray(structure.dex_previews)) throw new Error('compact dex_previews must be an array');
  if (structure.total_bytes !== result.total_bytes) throw new Error('compact total_bytes mismatch');
  if (structure.fields.length !== result.fields.length) throw new Error('compact field count mismatch');
  if (structure.fields.some((field) => 'raw_bytes' in field || 'summary' in field)) {
    throw new Error('compact fields must omit raw_bytes and summary');
  }
  const compactByteFields = structure.fields.filter(
    (field) => field.type === 'bytes' || field.type === 'padding',
  );
  if (compactByteFields.length === 0) throw new Error('expected a compact byte or padding field');
  if (compactByteFields.some((field) => 'parsed_value' in field)) {
    throw new Error('compact byte and padding fields must omit parsed_value');
  }

  console.log(
    `WASM bridge OK: ${result.fields.length} fields, compact structure excludes raw byte arrays`,
  );
  process.exit(0);
} catch (error) {
  console.error(error);
  process.exit(1);
}
