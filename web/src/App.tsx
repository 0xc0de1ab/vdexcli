import { useCallback, useEffect, useRef, useState } from 'react';
import {
  AlertCircle,
  Binary,
  Clock3,
  FileArchive,
  Loader2,
  RotateCcw,
  UploadCloud,
} from 'lucide-react';

import VdexTreeGrid from './VdexTreeGrid';
import heroImage from './assets/hero.png';
import type {
  StructureAnalysis,
  StructureChildren,
  StructureNode,
  WorkerRequest,
  WorkerResponse,
} from './worker-protocol';

interface VdexError {
  error: string;
}

interface ProgressState {
  label: string;
  detail: string;
  percent?: number;
}

interface AnalysisResponse {
  analysisId: number;
  result: unknown;
  sourceBuffer: ArrayBuffer;
  analysisMs: number;
  treeMs: number;
}

type TreeWorkerResponse = Extract<WorkerResponse, { type: 'children' | 'offset-path' }>;

interface PendingTreeRequest {
  resolve: (response: TreeWorkerResponse) => void;
  reject: (reason: Error) => void;
}

interface PendingAnalysis {
  requestId: number;
  resolve: (response: AnalysisResponse) => void;
  reject: (reason: Error) => void;
}

const isVdexError = (value: unknown): value is VdexError =>
  typeof value === 'object' && value !== null &&
  'error' in value && typeof (value as VdexError).error === 'string';

const normalizeStructureAnalysis = (value: unknown): StructureAnalysis | null => {
  if (typeof value !== 'object' || value === null) return null;
  const candidate = value as Partial<StructureAnalysis>;
  if (
    typeof candidate.total_bytes !== 'number' ||
    typeof candidate.field_count !== 'number' ||
    typeof candidate.root !== 'object' ||
    candidate.root === null ||
    !Array.isArray(candidate.initial_children) ||
    !Array.isArray(candidate.unmapped_gaps)
  ) return null;
  return candidate as StructureAnalysis;
};

const formatBytes = (bytes: number): string => {
  if (bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const unitIndex = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / 1024 ** unitIndex;
  return `${Number(value.toFixed(2)).toLocaleString()} ${units[unitIndex]}`;
};

const formatDuration = (milliseconds: number): string => {
  if (milliseconds < 1000) return `${Math.round(milliseconds)} ms`;
  return `${(milliseconds / 1000).toFixed(1)} s`;
};

const readFile = (file: File, onProgress: (loaded: number, total: number) => void) =>
  new Promise<ArrayBuffer>((resolve, reject) => {
    const reader = new FileReader();
    reader.onprogress = (event) => onProgress(event.loaded, event.total || file.size);
    reader.onload = () => {
      if (reader.result instanceof ArrayBuffer) resolve(reader.result);
      else reject(new Error('Failed to read the selected file'));
    };
    reader.onerror = () => reject(reader.error ?? new Error('Failed to read the selected file'));
    reader.onabort = () => reject(new Error('File reading was canceled'));
    reader.readAsArrayBuffer(file);
  });

export default function App() {
  const [isDragging, setIsDragging] = useState(false);
  const [isProcessing, setIsProcessing] = useState(false);
  const [data, setData] = useState<StructureAnalysis | null>(null);
  const [sourceBytes, setSourceBytes] = useState<Uint8Array | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [fileName, setFileName] = useState('');
  const [fileSize, setFileSize] = useState(0);
  const [engineStatus, setEngineStatus] = useState<'loading' | 'ready' | 'error'>('loading');
  const [progress, setProgress] = useState<ProgressState | null>(null);
  const [elapsedMs, setElapsedMs] = useState(0);
  const [analysisMs, setAnalysisMs] = useState<number | null>(null);
  const [treeMs, setTreeMs] = useState<number | null>(null);

  const workerRef = useRef<Worker | null>(null);
  const pendingRef = useRef<PendingAnalysis | null>(null);
  const pendingTreeRef = useRef(new Map<number, PendingTreeRequest>());
  const analysisIdRef = useRef<number | null>(null);
  const nextRequestId = useRef(1);
  const processingStartedAt = useRef<number | null>(null);

  useEffect(() => {
    const worker = new Worker(new URL('./vdex.worker.ts', import.meta.url), { type: 'classic' });
    const pendingTreeRequests = pendingTreeRef.current;
    workerRef.current = worker;

    worker.onmessage = (event: MessageEvent<WorkerResponse>) => {
      const message = event.data;
      if (message.type === 'ready') {
        setEngineStatus('ready');
        return;
      }
      if (message.type === 'progress') {
        if (pendingRef.current?.requestId === message.requestId) {
          setProgress({ label: message.label, detail: message.detail, percent: message.percent });
        }
        return;
      }
      if (message.type === 'result') {
        if (pendingRef.current?.requestId === message.requestId) {
          const pending = pendingRef.current;
          pendingRef.current = null;
          pending.resolve({
            analysisId: message.requestId,
            result: message.result,
            sourceBuffer: message.sourceBuffer,
            analysisMs: message.analysisMs,
            treeMs: message.treeMs,
          });
        }
        return;
      }
      if (message.type === 'children' || message.type === 'offset-path') {
        const pending = pendingTreeRequests.get(message.requestId);
        if (pending) {
          pendingTreeRequests.delete(message.requestId);
          pending.resolve(message);
        }
        return;
      }

      const pending = pendingRef.current;
      if (message.requestId !== undefined && pending?.requestId === message.requestId) {
        pendingRef.current = null;
        pending.reject(new Error(message.message));
      } else if (message.requestId !== undefined && pendingTreeRequests.has(message.requestId)) {
        const treePending = pendingTreeRequests.get(message.requestId);
        pendingTreeRequests.delete(message.requestId);
        treePending?.reject(new Error(message.message));
      } else {
        setEngineStatus('error');
        setError(message.message);
      }
    };

    worker.onerror = (event) => {
      const workerError = new Error(event.message || 'WASM worker failed');
      const pending = pendingRef.current;
      pendingRef.current = null;
      pending?.reject(workerError);
      for (const treePending of pendingTreeRequests.values()) treePending.reject(workerError);
      pendingTreeRequests.clear();
      setEngineStatus('error');
      setError(workerError.message);
    };

    const initMessage: WorkerRequest = { type: 'init', baseUrl: import.meta.env.BASE_URL };
    worker.postMessage(initMessage);

    return () => {
      worker.terminate();
      for (const pending of pendingTreeRequests.values()) {
        pending.reject(new Error('VDEX analysis worker was closed'));
      }
      pendingTreeRequests.clear();
      if (workerRef.current === worker) workerRef.current = null;
    };
  }, []);

  useEffect(() => {
    if (!isProcessing || processingStartedAt.current === null) return;
    const updateElapsed = () => {
      if (processingStartedAt.current !== null) {
        setElapsedMs(performance.now() - processingStartedAt.current);
      }
    };
    updateElapsed();
    const timer = window.setInterval(updateElapsed, 100);
    return () => window.clearInterval(timer);
  }, [isProcessing]);

  const processFile = async (file: File) => {
    const worker = workerRef.current;
    if (!worker || engineStatus !== 'ready') {
      setError('VDEX analysis engine is not ready');
      return;
    }

    setFileName(file.name);
    setFileSize(file.size);
    setIsProcessing(true);
    setError(null);
    setData(null);
    setSourceBytes(null);
    setAnalysisMs(null);
    setTreeMs(null);
    analysisIdRef.current = null;
    for (const pending of pendingTreeRef.current.values()) {
      pending.reject(new Error('A new VDEX analysis was started'));
    }
    pendingTreeRef.current.clear();
    setElapsedMs(0);
    setProgress({ label: 'Reading file', detail: `0 B of ${formatBytes(file.size)}`, percent: 0 });
    processingStartedAt.current = performance.now();

    try {
      const buffer = await readFile(file, (loaded, total) => {
        const percent = total > 0 ? Math.min(100, Math.round((loaded / total) * 100)) : undefined;
        setProgress({
          label: 'Reading file',
          detail: `${formatBytes(loaded)} of ${formatBytes(total)}`,
          percent,
        });
      });

      const requestId = nextRequestId.current++;
      const response = await new Promise<AnalysisResponse>((resolve, reject) => {
        pendingRef.current = { requestId, resolve, reject };
        const analyzeMessage: WorkerRequest = { type: 'analyze', requestId, buffer };
        worker.postMessage(analyzeMessage, [buffer]);
      });

      if (isVdexError(response.result)) throw new Error(response.result.error);
      const structure = normalizeStructureAnalysis(response.result);
      if (!structure) throw new Error('WASM returned an invalid analysis result');
      if (response.sourceBuffer.byteLength !== structure.total_bytes) {
        throw new Error('WASM returned a mismatched source byte buffer');
      }

      setProgress({
        label: 'Rendering analysis',
        detail: `${structure.field_count.toLocaleString()} fields organized`,
        percent: 100,
      });
      setAnalysisMs(response.analysisMs);
      setTreeMs(response.treeMs);
      analysisIdRef.current = response.analysisId;
      setSourceBytes(new Uint8Array(response.sourceBuffer));
      setData(structure);
    } catch (caught) {
      console.error(caught);
      setError(caught instanceof Error ? caught.message : 'Failed to process file');
    } finally {
      if (processingStartedAt.current !== null) {
        setElapsedMs(performance.now() - processingStartedAt.current);
      }
      processingStartedAt.current = null;
      setIsProcessing(false);
    }
  };

  const onDrop = (event: React.DragEvent) => {
    event.preventDefault();
    setIsDragging(false);
    const file = event.dataTransfer.files[0];
    if (file) void processFile(file);
  };

  const onFileInput = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) void processFile(file);
  };

  const reset = () => {
    setData(null);
    setSourceBytes(null);
    setError(null);
    setProgress(null);
    setFileName('');
    setFileSize(0);
    setAnalysisMs(null);
    setTreeMs(null);
    analysisIdRef.current = null;
    for (const pending of pendingTreeRef.current.values()) {
      pending.reject(new Error('The VDEX analysis was closed'));
    }
    pendingTreeRef.current.clear();
  };

  const requestTreeData = useCallback((message: WorkerRequest): Promise<TreeWorkerResponse> => {
    const worker = workerRef.current;
    if (!worker) return Promise.reject(new Error('VDEX analysis worker is unavailable'));
    if (message.type !== 'children' && message.type !== 'find-offset') {
      return Promise.reject(new Error('Invalid tree request'));
    }
    return new Promise((resolve, reject) => {
      pendingTreeRef.current.set(message.requestId, { resolve, reject });
      try {
        worker.postMessage(message);
      } catch (caught) {
        pendingTreeRef.current.delete(message.requestId);
        reject(caught instanceof Error ? caught : new Error('Failed to request VDEX tree data'));
      }
    });
  }, []);

  const loadTreeChildren = useCallback(async (nodeId: number): Promise<StructureNode[]> => {
    const analysisId = analysisIdRef.current;
    if (analysisId === null) throw new Error('No active VDEX analysis');
    const requestId = nextRequestId.current++;
    const response = await requestTreeData({ type: 'children', requestId, analysisId, nodeId });
    if (response.type !== 'children' || response.analysisId !== analysisId || response.nodeId !== nodeId) {
      throw new Error('VDEX worker returned mismatched tree children');
    }
    return response.children;
  }, [requestTreeData]);

  const findTreeOffset = useCallback(async (
    offset: number,
  ): Promise<{ path: StructureNode[]; branches: StructureChildren[] }> => {
    const analysisId = analysisIdRef.current;
    if (analysisId === null) throw new Error('No active VDEX analysis');
    const requestId = nextRequestId.current++;
    const response = await requestTreeData({ type: 'find-offset', requestId, analysisId, offset });
    if (response.type !== 'offset-path' || response.analysisId !== analysisId) {
      throw new Error('VDEX worker returned a mismatched offset path');
    }
    return { path: response.path, branches: response.branches };
  }, [requestTreeData]);

  return (
    <div className={`app-shell${data ? ' has-analysis' : ''}`}>
      <header className="app-header">
        <div className="brand-lockup">
          <span className="brand-mark"><Binary size={19} /></span>
          <div>
            <h1>VDEX Analyzer</h1>
            <span>Physical byte structure explorer</span>
          </div>
        </div>
        {data && (
          <button type="button" className="secondary-button" onClick={reset}>
            <RotateCcw size={16} /> New analysis
          </button>
        )}
      </header>

      <main>
        {engineStatus === 'loading' && !data && !isProcessing && (
          <div className="engine-loading" aria-live="polite">
            <Loader2 size={24} className="spinner" />
            <span>Loading analysis engine...</span>
          </div>
        )}

        {engineStatus === 'ready' && !data && !isProcessing && (
          <section className="upload-view">
            <img src={heroImage} alt="Layered binary file structure" />
            <div className="upload-copy">
              <span className="eyebrow">Local WASM analysis</span>
              <h2>Open a VDEX file</h2>
              <p>The file stays in this browser while its headers, arrays, and byte ranges are mapped.</p>
            </div>
            <label
              className={`dropzone${isDragging ? ' active' : ''}`}
              onDragOver={(event) => { event.preventDefault(); setIsDragging(true); }}
              onDragLeave={() => setIsDragging(false)}
              onDrop={onDrop}
            >
              <input
                type="file"
                className="visually-hidden"
                accept=".vdex,.dm,application/octet-stream"
                onChange={onFileInput}
              />
              <UploadCloud size={30} />
              <span>{isDragging ? 'Drop the file here' : 'Drop a .vdex file or choose one'}</span>
              <small>VDEX and DM binary files</small>
            </label>
          </section>
        )}

        {isProcessing && progress && (
          <section className="progress-panel" aria-live="polite">
            <div className="progress-header">
              <div className="progress-status">
                <Loader2 size={24} className="spinner" />
                <div>
                  <strong>{progress.label}</strong>
                  <span>{fileName} · {progress.detail}</span>
                </div>
              </div>
              <span className="elapsed-time"><Clock3 size={16} /> {formatDuration(elapsedMs)}</span>
            </div>
            <div
              className="progress-track"
              role="progressbar"
              aria-label={progress.label}
              aria-valuemin={0}
              aria-valuemax={100}
              aria-valuenow={progress.percent}
            >
              <div
                className={`progress-fill${progress.percent === undefined ? ' indeterminate' : ''}`}
                style={progress.percent === undefined ? undefined : { width: `${progress.percent}%` }}
              />
            </div>
            <p>Large files may spend most of their time decoding DEX and verifier arrays.</p>
          </section>
        )}

        {error && (
          <section className="error-panel" role="alert">
            <AlertCircle size={21} />
            <div><strong>Analysis failed</strong><p>{error}</p></div>
          </section>
        )}

        {data && sourceBytes && !isProcessing && (
          <div className="analysis-view">
            <section className="analysis-summary" aria-label="Analysis summary">
              <div className="file-identity">
                <FileArchive size={18} />
                <div><strong>{fileName}</strong><span>{formatBytes(fileSize)}</span></div>
              </div>
              <dl>
                <div><dt>Total bytes</dt><dd>{data.total_bytes.toLocaleString()}</dd></div>
                <div><dt>Parsed fields</dt><dd>{data.field_count.toLocaleString()}</dd></div>
                <div><dt>Unmapped gaps</dt><dd>{data.unmapped_gaps.length.toLocaleString()}</dd></div>
                <div><dt>WASM parse</dt><dd>{analysisMs === null ? '-' : formatDuration(analysisMs)}</dd></div>
                <div><dt>Tree build</dt><dd>{treeMs === null ? '-' : formatDuration(treeMs)}</dd></div>
                <div><dt>Total time</dt><dd>{formatDuration(elapsedMs)}</dd></div>
              </dl>
            </section>
            <VdexTreeGrid
              root={data.root}
              initialChildren={data.initial_children}
              sourceBytes={sourceBytes}
              loadChildren={loadTreeChildren}
              findOffset={findTreeOffset}
            />
          </div>
        )}
      </main>
    </div>
  );
}
