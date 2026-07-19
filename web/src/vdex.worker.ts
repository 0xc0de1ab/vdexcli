// Keep these local so Vite serves this file as a classic worker in development.
type WorkerRequest =
  | { type: 'init'; baseUrl: string }
  | { type: 'analyze'; requestId: number; buffer: ArrayBuffer };

type WorkerResponse =
  | { type: 'ready' }
  | {
      type: 'progress';
      requestId: number;
      stage: 'analyzing' | 'preparing';
      label: string;
      detail: string;
      percent?: number;
    }
  | { type: 'result'; requestId: number; result: unknown; analysisMs: number }
  | { type: 'error'; requestId?: number; message: string };

interface GoRuntime {
  importObject: WebAssembly.Imports;
  run: (instance: WebAssembly.Instance) => Promise<void>;
}

interface VdexApi {
  explain: (data: Uint8Array) => unknown;
}

interface WorkerScope {
  Go?: new () => GoRuntime;
  vdex?: VdexApi;
  onmessage: ((event: MessageEvent<WorkerRequest>) => void) | null;
  importScripts: (...urls: string[]) => void;
  postMessage: (message: WorkerResponse) => void;
}

const scope = globalThis as unknown as WorkerScope;
let engineReady: Promise<void> | null = null;

const messageFromError = (error: unknown): string =>
  error instanceof Error ? error.message : String(error);

const waitForApi = async () => {
  for (let attempt = 0; attempt < 100 && !scope.vdex; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  if (!scope.vdex) throw new Error('VDEX WASM API was not registered');
};

const initialize = async (baseUrl: string) => {
  const runtimeUrl = `${baseUrl}wasm_exec.js`;
  scope.importScripts(runtimeUrl);
  if (!scope.Go) throw new Error('Go WASM runtime is unavailable');

  const go = new scope.Go();
  const response = await fetch(`${baseUrl}vdex.wasm`);
  if (!response.ok) {
    throw new Error(`WASM request failed: ${response.status} ${response.statusText}`);
  }

  let result: WebAssembly.WebAssemblyInstantiatedSource;
  try {
    result = await WebAssembly.instantiateStreaming(response.clone(), go.importObject);
  } catch {
    result = await WebAssembly.instantiate(await response.arrayBuffer(), go.importObject);
  }
  void go.run(result.instance);
  await waitForApi();
};

const analyze = async (requestId: number, buffer: ArrayBuffer) => {
  await engineReady;
  if (!scope.vdex) throw new Error('VDEX WASM API is unavailable');

  scope.postMessage({
    type: 'progress',
    requestId,
    stage: 'analyzing',
    label: 'Analyzing VDEX structure',
    detail: `${buffer.byteLength.toLocaleString()} bytes loaded`,
  });

  const startedAt = performance.now();
  const result = scope.vdex.explain(new Uint8Array(buffer));
  const parsedResult = typeof result === 'string' ? JSON.parse(result) : result;
  const analysisMs = performance.now() - startedAt;
  const fields =
    typeof parsedResult === 'object' && parsedResult !== null &&
    Array.isArray((parsedResult as { fields?: unknown }).fields)
      ? (parsedResult as { fields: unknown[] }).fields
      : [];

  scope.postMessage({
    type: 'progress',
    requestId,
    stage: 'preparing',
    label: 'Preparing analysis results',
    detail: `${fields.length.toLocaleString()} fields parsed`,
    percent: 90,
  });

  for (const field of fields) {
    if (typeof field !== 'object' || field === null) continue;
    const compactField = field as Record<string, unknown>;
    delete compactField.raw_bytes;
    delete compactField.summary;
  }
  scope.postMessage({ type: 'result', requestId, result: parsedResult, analysisMs });
};

scope.onmessage = (event) => {
  const message = event.data;
  if (message.type === 'init') {
    engineReady = initialize(message.baseUrl);
    void engineReady
      .then(() => scope.postMessage({ type: 'ready' }))
      .catch((error: unknown) => {
        scope.postMessage({ type: 'error', message: messageFromError(error) });
      });
    return;
  }

  void analyze(message.requestId, message.buffer).catch((error: unknown) => {
    scope.postMessage({
      type: 'error',
      requestId: message.requestId,
      message: messageFromError(error),
    });
  });
};
