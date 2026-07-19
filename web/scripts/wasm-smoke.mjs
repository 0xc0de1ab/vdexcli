import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const [wasmArgument, runtimeArgument] = process.argv.slice(2);
if (!wasmArgument || !runtimeArgument) {
  console.error('usage: node scripts/wasm-smoke.mjs <vdex.wasm> <wasm_exec.js>');
  process.exit(2);
}

const buildMinimalVdex = () => {
  const data = new Uint8Array(64);
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

  const result = globalThis.vdex?.explain(buildMinimalVdex());
  if (!result || result.error) throw new Error(result?.error ?? 'WASM API returned no result');
  if (!Array.isArray(result.fields)) throw new Error('fields must be an array');
  if (!Array.isArray(result.unmapped_gaps)) throw new Error('unmapped_gaps must be an array');
  if (result.total_bytes !== 64) throw new Error(`unexpected total_bytes: ${result.total_bytes}`);

  console.log(`WASM bridge OK: ${result.fields.length} fields, ${result.unmapped_gaps.length} gaps`);
  process.exit(0);
} catch (error) {
  console.error(error);
  process.exit(1);
}
