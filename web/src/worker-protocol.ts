export type AnalysisStage = 'analyzing' | 'preparing';

export type WorkerRequest =
  | { type: 'init'; baseUrl: string }
  | { type: 'analyze'; requestId: number; buffer: ArrayBuffer };

export type WorkerResponse =
  | { type: 'ready' }
  | {
      type: 'progress';
      requestId: number;
      stage: AnalysisStage;
      label: string;
      detail: string;
      percent?: number;
    }
  | { type: 'result'; requestId: number; result: unknown; analysisMs: number }
  | { type: 'error'; requestId?: number; message: string };
