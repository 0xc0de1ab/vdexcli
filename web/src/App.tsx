import { useEffect, useState } from 'react';
import { UploadCloud, FileJson, Loader2, Database, AlertCircle, RotateCcw } from 'lucide-react';

interface Field {
  offset: number;
  size: number;
  type: string;
  raw_bytes: number[];
  parsed_value: any;
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

// Ensure TypeScript knows about window.vdex
declare global {
  interface Window {
    vdex?: {
      explain: (data: Uint8Array) => string | PrimitiveMap | VdexError;
    };
    vdexReady?: Promise<void>;
  }
}

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
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
};

const toHex = (num: number, padding: number = 2): string => {
  return num.toString(16).padStart(padding, '0').toUpperCase();
};

export default function App() {
  const [isDragging, setIsDragging] = useState(false);
  const [isProcessing, setIsProcessing] = useState(false);
  const [data, setData] = useState<PrimitiveMap | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [fileName, setFileName] = useState<string>('');
  const [engineStatus, setEngineStatus] = useState<'loading' | 'ready' | 'error'>('loading');

  useEffect(() => {
    const ready = window.vdexReady;
    if (!ready) {
      setEngineStatus('error');
      setError('WASM loader was not initialized');
      return;
    }
    ready.then(() => setEngineStatus('ready')).catch((err: unknown) => {
      setEngineStatus('error');
      setError(err instanceof Error ? err.message : 'Failed to load WASM engine');
    });
  }, []);

  const processFile = async (file: File) => {
    setFileName(file.name);
    setIsProcessing(true);
    setError(null);
    setData(null);
    
    try {
      const buffer = await file.arrayBuffer();
      const uint8Array = new Uint8Array(buffer);
      
      await window.vdexReady;
      if (!window.vdex?.explain) {
        throw new Error('VDEX WASM API is unavailable');
      }
      const result = window.vdex.explain(uint8Array);
      const parsedResult: unknown = typeof result === 'string' ? JSON.parse(result) : result;
      if (isVdexError(parsedResult)) {
        throw new Error(parsedResult.error);
      }
      const primitiveMap = normalizePrimitiveMap(parsedResult);
      if (!primitiveMap) {
        throw new Error('WASM returned an invalid analysis result');
      }
      setData(primitiveMap);
    } catch (err) {
      console.error(err);
      setError(err instanceof Error ? err.message : "Failed to process file");
    } finally {
      setIsProcessing(false);
    }
  };

  const onDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const onDragLeave = () => {
    setIsDragging(false);
  };

  const onDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      processFile(e.dataTransfer.files[0]);
    }
  };

  const onFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      processFile(e.target.files[0]);
    }
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
            onDragOver={onDragOver}
            onDragLeave={onDragLeave}
            onDrop={onDrop}
          >
            <input type="file" accept=".vdex,.dm,application/octet-stream" style={{ display: 'none' }} onChange={onFileInput} />
            <UploadCloud size={48} color={isDragging ? "#3b82f6" : "#94a3b8"} />
            <p>{isDragging ? "Drop it here!" : "Drag and drop a .vdex file, or click to select"}</p>
          </label>
        </div>
      )}

      {isProcessing && (
        <div className="glass-panel loading">
          <Loader2 size={48} className="spinner" />
          <p>Analyzing {fileName}...</p>
        </div>
      )}

      {error && (
        <div className="glass-panel" style={{ borderColor: 'var(--danger)', color: 'var(--danger)', display: 'flex', gap: '1rem', alignItems: 'center' }}>
          <AlertCircle size={24} />
          <p>{error}</p>
        </div>
      )}

      {data && !isProcessing && (
        <div className="dashboard">
          <div className="summary-panel">
            <div className="stat-card">
              <h3>Total Size</h3>
              <div className="value">{formatBytes(data.total_bytes)}</div>
            </div>
            <div className="stat-card">
              <h3>Parsed Fields</h3>
              <div className="value">{data.fields.length}</div>
            </div>
            <div className="stat-card">
              <h3>Unmapped Gaps</h3>
              <div className="value">{data.unmapped_gaps.length}</div>
            </div>
            <button 
              className="glass-panel" 
              style={{ cursor: 'pointer', textAlign: 'center', transition: 'all 0.2s', padding: '1rem' }}
              onClick={() => { setData(null); setError(null); }}
            >
              <RotateCcw size={18} aria-hidden="true" /> Analyze Another File
            </button>
          </div>

          <div className="detail-panel glass-panel">
            <h2 style={{ marginBottom: '1.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Database size={24} color="var(--accent-primary)" />
              File Structure Breakdown
            </h2>
            
            <div className="field-list">
              {data.fields.map((field, idx) => (
                <div key={idx} className="field-item">
                  <div className="field-info">
                    <span className="field-path">
                      <FileJson size={14} style={{ display: 'inline', marginRight: '4px', verticalAlign: 'text-bottom' }}/>
                      {field.logical_path}
                    </span>
                    <span className="field-desc">{field.description}</span>
                  </div>
                  <div className="field-data">
                    <span className="field-value">
                      {typeof field.parsed_value === 'string' ? `"${field.parsed_value}"` : field.parsed_value}
                    </span>
                    <span className="field-meta">
                      0x{toHex(field.offset, 4)} ({field.size} bytes) 
                    </span>
                  </div>
                </div>
              ))}
              
              {data.unmapped_gaps.map((gap, idx) => (
                <div key={`gap-${idx}`} className="field-item" style={{ borderStyle: 'dashed', borderColor: 'rgba(255,255,255,0.1)' }}>
                  <div className="field-info">
                    <span className="field-path" style={{ color: 'var(--text-muted)' }}>[Unmapped Data]</span>
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
          </div>
        </div>
      )}
    </div>
  );
}
