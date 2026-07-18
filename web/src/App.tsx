import { useState } from 'react';
import { UploadCloud, FileJson, Loader2, Database, AlertCircle } from 'lucide-react';

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
  offset: number;
  size: number;
}

interface PrimitiveMap {
  total_bytes: number;
  fields: Field[];
  unmapped_gaps: Gap[];
}

// Ensure TypeScript knows about window.vdex
declare global {
  interface Window {
    vdex?: {
      explain: (data: Uint8Array) => string | PrimitiveMap;
    };
  }
}

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

  const processFile = async (file: File) => {
    setFileName(file.name);
    setIsProcessing(true);
    setError(null);
    
    try {
      const buffer = await file.arrayBuffer();
      const uint8Array = new Uint8Array(buffer);
      
      // Try to call WASM module if available
      if (window.vdex && window.vdex.explain) {
        console.log("Calling window.vdex.explain...");
        const result = window.vdex.explain(uint8Array);
        
        let parsedResult: PrimitiveMap;
        if (typeof result === 'string') {
          parsedResult = JSON.parse(result);
        } else {
          parsedResult = result;
        }
        setData(parsedResult);
      } else {
        console.warn("window.vdex.explain not found, using mock data");
        // Mock data
        setTimeout(() => {
          setData({
            total_bytes: uint8Array.length,
            fields: [
              {
                offset: 0, size: 4, type: "string",
                raw_bytes: [118, 100, 101, 120], parsed_value: "vdex",
                logical_path: "vdex.header.magic", description: "VDEX Magic Signature"
              },
              {
                offset: 4, size: 4, type: "string",
                raw_bytes: [48, 50, 49, 0], parsed_value: "021",
                logical_path: "vdex.header.version", description: "VDEX Version (e.g. 021 for Oreo)"
              },
              {
                offset: 8, size: 4, type: "uint32",
                raw_bytes: [2, 0, 0, 0], parsed_value: 2,
                logical_path: "vdex.header.number_of_dex_files", description: "Number of DEX files"
              }
            ],
            unmapped_gaps: [
              { offset: 12, size: uint8Array.length - 12 }
            ]
          });
          setIsProcessing(false);
        }, 1000);
        return; // wait for timeout
      }
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

      {!data && !isProcessing && (
        <div className="glass-panel">
          <label 
            className={`dropzone ${isDragging ? 'active' : ''}`}
            onDragOver={onDragOver}
            onDragLeave={onDragLeave}
            onDrop={onDrop}
          >
            <input type="file" style={{ display: 'none' }} onChange={onFileInput} />
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
              onClick={() => setData(null)}
            >
              Analyze Another File
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
                      0x{toHex(gap.offset, 4)} ({gap.size} bytes)
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
