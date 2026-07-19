export type AnalysisStage = 'analyzing' | 'preparing';

export type StructureNodeKind = 'root' | 'group' | 'array' | 'range' | 'item' | 'field' | 'gap';

export interface StructureNode {
  id: number;
  key: string;
  kind: StructureNodeKind;
  offset: number;
  span: number;
  covered_bytes: number;
  contiguous: boolean;
  field_count: number;
  index?: number;
  item_count?: number;
  item_size?: number;
  type?: string;
  value?: unknown;
  description?: string;
  declared_offset?: number;
  declared_size?: number;
  preview_offset: number;
  preview_span: number;
  child_count: number;
}

export interface StructureChildren {
  node_id: number;
  children: StructureNode[];
}

export interface Gap {
  start: number;
  end: number;
}

export interface StructureAnalysis {
  total_bytes: number;
  field_count: number;
  root: StructureNode;
  initial_children: StructureChildren[];
  unmapped_gaps: Gap[];
}

export type WorkerRequest =
  | { type: 'init'; baseUrl: string }
  | { type: 'analyze'; requestId: number; buffer: ArrayBuffer }
  | { type: 'children'; requestId: number; analysisId: number; nodeId: number }
  | { type: 'find-offset'; requestId: number; analysisId: number; offset: number };

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
  | {
      type: 'result';
      requestId: number;
      result: unknown;
      sourceBuffer: ArrayBuffer;
      analysisMs: number;
      treeMs: number;
    }
  | {
      type: 'children';
      requestId: number;
      analysisId: number;
      nodeId: number;
      children: StructureNode[];
    }
  | {
      type: 'offset-path';
      requestId: number;
      analysisId: number;
      path: StructureNode[];
      branches: StructureChildren[];
    }
  | { type: 'error'; requestId?: number; message: string };
