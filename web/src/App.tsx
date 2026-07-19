import { useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertCircle,
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  Clock3,
  Database,
  FileJson,
  Loader2,
  RotateCcw,
  UploadCloud,
} from 'lucide-react';

import type { WorkerRequest, WorkerResponse } from './worker-protocol';

interface Field {
  offset: number;
  size: number;
  type: string;
  parsed_value: unknown;
  logical_path: string;
  description: string;
}

interface Gap {
  start: number;
  end: number;
}

interface PrimitiveMap {
  total_bytes: number;
  fields: Field[];
  unmapped_gaps: Gap[];
}

interface VdexError {
  error: string;
}

interface ProgressState {
  label: string;
  detail: string;
  percent?: number;
}

interface AnalysisResponse {
  result: unknown;
  analysisMs: number;
}

interface PendingAnalysis {
  requestId: number;
  resolve: (response: AnalysisResponse) => void;
  reject: (reason: Error) => void;
}

interface PaginationProps {
  page: number;
  pageCount: number;
  rangeStart: number;
  rangeEnd: number;
  total: number;
  onPageChange: (page: number) => void;
}

const FIELDS_PER_PAGE = 200;

const isVdexError = (value: unknown): value is VdexError =>
  typeof value === 'object' && value !== null &&
  'error' in value && typeof (value as VdexError).error === 'string';

const normalizePrimitiveMap = (value: unknown): PrimitiveMap | null => {
  if (typeof value !== 'object' || value === null) return null;

  const candidate = value as Record<string, unknown>;
  if (typeof candidate.total_bytes !== 'number' || !Array.isArray(candidate.fields)) return null;
  if (candidate.unmapped_gaps !== null && !Array.isArray(candidate.unmapped_gaps)) return null;

  return {
    ...candidate,
    total_bytes: candidate.total_bytes,
    fields: candidate.fields,
    unmapped_gaps: candidate.unmapped_gaps ?? [],
  } as PrimitiveMap;
};

const formatBytes = (bytes: number): string => {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
};

const formatDuration = (milliseconds: number): string => {
  if (milliseconds < 1000) return `${Math.round(milliseconds)} ms`;
  return `${(milliseconds / 1000).toFixed(1)} s`;
};

const formatValue = (value: unknown): string => {
  if (typeof value === 'string') return `"${value}"`;
  if (value === null) return 'null';
  if (typeof value === 'object') return JSON.stringify(value) ?? String(value);
  return String(value);
};

const toHex = (num: number, padding = 2): string =>
  num.toString(16).padStart(padding, '0').toUpperCase();

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

function Pagination({
  page,
  pageCount,
  rangeStart,
  rangeEnd,
  total,
  onPageChange,
}: PaginationProps) {
  if (pageCount <= 1) return null;

  return (
    <nav className="pagination" aria-label="Field pages">
      <span className="pagination-range">
        {rangeStart.toLocaleString()}-{rangeEnd.toLocaleString()} of {total.toLocaleString()}
      </span>
      <div className="pagination-controls">
        <button
          type="button"
          className="icon-button"
          onClick={() => onPageChange(0)}
          disabled={page === 0}
          aria-label="First page"
          title="First page"
        >
          <ChevronsLeft size={18} />
        </button>
        <button
          type="button"
          className="icon-button"
          onClick={() => onPageChange(page - 1)}
          disabled={page === 0}
          aria-label="Previous page"
          title="Previous page"
        >
          <ChevronLeft size={18} />
        </button>
        <span className="pagination-page">{page + 1} / {pageCount.toLocaleString()}</span>
        <button
          type="button"
          className="icon-button"
          onClick={() => onPageChange(page + 1)}
          disabled={page >= pageCount - 1}
          aria-label="Next page"
          title="Next page"
        >
          <ChevronRight size={18} />
        </button>
        <button
          type="button"
          className="icon-button"
          onClick={() => onPageChange(pageCount - 1)}
          disabled={page >= pageCount - 1}
          aria-label="Last page"
          title="Last page"
        >
          <ChevronsRight size={18} />
        </button>
      </div>
    </nav>
  );
}

export default function App() {
  const [isDragging, setIsDragging] = useState(false);
  const [isProcessing, setIsProcessing] = useState(false);
  const [data, setData] = useState<PrimitiveMap | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [fileName, setFileName] = useState('');
  const [fileSize, setFileSize] = useState(0);
  const [engineStatus, setEngineStatus] = useState<'loading' | 'ready' | 'error'>('loading');
  const [progress, setProgress] = useState<ProgressState | null>(null);
  const [elapsedMs, setElapsedMs] = useState(0);
  const [analysisMs, setAnalysisMs] = useState<number | null>(null);
  const [page, setPage] = useState(0);

  const workerRef = useRef<Worker | null>(null);
  const pendingRef = useRef<PendingAnalysis | null>(null);
  const nextRequestId = useRef(1);
  const processingStartedAt = useRef<number | null>(null);
  const detailPanelRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    const worker = new Worker(new URL('./vdex.worker.ts', import.meta.url), { type: 'classic' });
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
          pending.resolve({ result: message.result, analysisMs: message.analysisMs });
        }
        return;
      }

      const pending = pendingRef.current;
      if (message.requestId !== undefined && pending?.requestId === message.requestId) {
        pendingRef.current = null;
        pending.reject(new Error(message.message));
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
      setEngineStatus('error');
      setError(workerError.message);
    };

    const initMessage: WorkerRequest = { type: 'init', baseUrl: import.meta.env.BASE_URL };
    worker.postMessage(initMessage);

    return () => {
      worker.terminate();
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

  const pageCount = data ? Math.max(1, Math.ceil(data.fields.length / FIELDS_PER_PAGE)) : 1;
  const rangeStart = data && data.fields.length > 0 ? page * FIELDS_PER_PAGE + 1 : 0;
  const rangeEnd = data ? Math.min((page + 1) * FIELDS_PER_PAGE, data.fields.length) : 0;
  const visibleFields = useMemo(
    () => data?.fields.slice(page * FIELDS_PER_PAGE, (page + 1) * FIELDS_PER_PAGE) ?? [],
    [data, page],
  );

  const changePage = (nextPage: number) => {
    setPage(nextPage);
    window.requestAnimationFrame(() => {
      detailPanelRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  };

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
    setPage(0);
    setAnalysisMs(null);
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

      const requestId = nextRequestId.current;
      nextRequestId.current += 1;
      const response = await new Promise<AnalysisResponse>((resolve, reject) => {
        pendingRef.current = { requestId, resolve, reject };
        const analyzeMessage: WorkerRequest = { type: 'analyze', requestId, buffer };
        worker.postMessage(analyzeMessage, [buffer]);
      });

      if (isVdexError(response.result)) throw new Error(response.result.error);
      const primitiveMap = normalizePrimitiveMap(response.result);
      if (!primitiveMap) throw new Error('WASM returned an invalid analysis result');

      setProgress({
        label: 'Rendering analysis',
        detail: `${primitiveMap.fields.length.toLocaleString()} fields ready`,
        percent: 100,
      });
      setAnalysisMs(response.analysisMs);
      setData(primitiveMap);
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
    setError(null);
    setProgress(null);
    setFileName('');
    setFileSize(0);
    setPage(0);
  };

  return (
    <div className="app-container">
      <header className="header">
        <h1>VDEX Web Analyzer</h1>
        <p>Drop a compiled Android VDEX file to analyze its internal structure</p>
      </header>

      {engineStatus === 'loading' && !data && !isProcessing && (
        <div className="glass-panel loading">
          <Loader2 size={32} className="spinner" />
          <p>Loading analysis engine...</p>
        </div>
      )}

      {engineStatus === 'ready' && !data && !isProcessing && (
        <div className="glass-panel">
          <label
            className={`dropzone ${isDragging ? 'active' : ''}`}
            onDragOver={(event) => { event.preventDefault(); setIsDragging(true); }}
            onDragLeave={() => setIsDragging(false)}
            onDrop={onDrop}
          >
            <input
              type="file"
              accept=".vdex,.dm,application/octet-stream"
              hidden
              onChange={onFileInput}
            />
            <UploadCloud size={48} color={isDragging ? '#3b82f6' : '#94a3b8'} />
            <p>{isDragging ? 'Drop it here!' : 'Drag and drop a .vdex file, or click to select'}</p>
          </label>
        </div>
      )}

      {isProcessing && progress && (
        <div className="glass-panel progress-panel" aria-live="polite">
          <div className="progress-header">
            <div className="progress-status">
              <Loader2 size={30} className="spinner progress-spinner" />
              <div className="progress-copy">
                <strong>{progress.label}</strong>
                <span>{fileName} · {progress.detail}</span>
              </div>
            </div>
            <span className="elapsed-time"><Clock3 size={17} /> {formatDuration(elapsedMs)}</span>
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
              className={`progress-fill ${progress.percent === undefined ? 'indeterminate' : ''}`}
              style={progress.percent === undefined ? undefined : { width: `${progress.percent}%` }}
            />
          </div>
        </div>
      )}

      {error && (
        <div className="glass-panel error-panel">
          <AlertCircle size={24} />
          <p>{error}</p>
        </div>
      )}

      {data && !isProcessing && (
        <div className="dashboard">
          <aside className="summary-panel">
            <div className="stat-card">
              <h3>Total Size</h3>
              <div className="value">{formatBytes(data.total_bytes)}</div>
            </div>
            <div className="stat-card">
              <h3>Parsed Fields</h3>
              <div className="value">{data.fields.length.toLocaleString()}</div>
            </div>
            <div className="stat-card">
              <h3>Unmapped Gaps</h3>
              <div className="value">{data.unmapped_gaps.length.toLocaleString()}</div>
            </div>
            <div className="stat-card">
              <h3>WASM Time</h3>
              <div className="value">{analysisMs === null ? '-' : formatDuration(analysisMs)}</div>
            </div>
            <div className="file-summary">
              <span>{fileName}</span>
              <small>{formatBytes(fileSize)} · total {formatDuration(elapsedMs)}</small>
            </div>
            <button type="button" className="reset-button" onClick={reset}>
              <RotateCcw size={18} aria-hidden="true" /> Analyze Another File
            </button>
          </aside>

          <section ref={detailPanelRef} className="detail-panel glass-panel">
            <div className="detail-heading">
              <h2><Database size={24} /> File Structure Breakdown</h2>
              <Pagination
                page={page}
                pageCount={pageCount}
                rangeStart={rangeStart}
                rangeEnd={rangeEnd}
                total={data.fields.length}
                onPageChange={changePage}
              />
            </div>

            <div className="field-list">
              {visibleFields.map((field, index) => (
                <div key={`${field.offset}-${field.logical_path}-${index}`} className="field-item">
                  <div className="field-info">
                    <span className="field-path">
                      <FileJson size={14} aria-hidden="true" />
                      {field.logical_path}
                    </span>
                    <span className="field-desc">{field.description}</span>
                  </div>
                  <div className="field-data">
                    <span className="field-value">{formatValue(field.parsed_value)}</span>
                    <span className="field-meta">
                      0x{toHex(field.offset, 4)} ({field.size} bytes)
                    </span>
                  </div>
                </div>
              ))}

              {data.unmapped_gaps.map((gap, index) => (
                <div key={`gap-${index}`} className="field-item gap-item">
                  <div className="field-info">
                    <span className="field-path muted">[Unmapped Data]</span>
                    <span className="field-desc">Unknown or unparsed raw bytes</span>
                  </div>
                  <div className="field-data">
                    <span className="field-meta">
                      0x{toHex(gap.start, 4)} ({gap.end - gap.start} bytes)
                    </span>
                  </div>
                </div>
              ))}
            </div>

            <Pagination
              page={page}
              pageCount={pageCount}
              rangeStart={rangeStart}
              rangeEnd={rangeEnd}
              total={data.fields.length}
              onPageChange={changePage}
            />
          </section>
        </div>
      )}
    </div>
  );
}
