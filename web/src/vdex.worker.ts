// Keep these types local so Vite serves this file as a classic worker in development.
type WorkerRequest =
  | { type: 'init'; baseUrl: string }
  | { type: 'analyze'; requestId: number; buffer: ArrayBuffer }
  | { type: 'children'; requestId: number; analysisId: number; nodeId: number }
  | { type: 'find-offset'; requestId: number; analysisId: number; offset: number };

type StructureNodeKind = 'root' | 'group' | 'array' | 'range' | 'item' | 'field' | 'gap';

interface StructureNode {
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

interface StructureChildren {
  node_id: number;
  children: StructureNode[];
}

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
  postMessage: (message: WorkerResponse, transfer?: Transferable[]) => void;
}

interface RawField {
  offset: number;
  size: number;
  type: string;
  parsed_value: unknown;
  logical_path: string;
  description?: string;
}

interface PathToken {
  key: string;
  index?: number;
}

interface BuildNode {
  id: number;
  key: string;
  index?: number;
  terminals?: RawField[];
  childMap?: Map<string, BuildNode>;
  children: BuildNode[];
  kind?: StructureNodeKind;
  offset?: number;
  span?: number;
  covered_bytes?: number;
  contiguous?: boolean;
  field_count?: number;
  item_count?: number;
  item_size?: number;
  type?: string;
  value?: unknown;
  description?: string;
  declared_offset?: number;
  declared_size?: number;
  preview_offset?: number;
  preview_span?: number;
}

interface SectionDeclaration {
  offset?: number;
  size?: number;
}

const ARRAY_CHUNK_SIZE = 256;
const scope = globalThis as unknown as WorkerScope;
let engineReady: Promise<void> | null = null;
let nextNodeId = 1;
let activeAnalysis: { requestId: number; root: BuildNode; nodes: Map<number, BuildNode> } | null = null;

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

const newBuildNode = (key: string, index?: number): BuildNode => ({
  id: nextNodeId++,
  key,
  index,
  terminals: [],
  childMap: new Map(),
  children: [],
});

const tokenizePath = (path: string): PathToken[] => {
  const tokens: PathToken[] = [];
  const pattern = /([^.[]+)|\[(\d+)\]/g;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(path)) !== null) {
    if (match[2] !== undefined) {
      const index = Number(match[2]);
      tokens.push({ key: `[${index}]`, index });
    } else {
      tokens.push({ key: match[1] });
    }
  }
  const structureTokens = tokens[0]?.key === 'vdex' ? tokens.slice(1) : tokens;
  // Align4 is emitted under vdex.dexes, but those bytes belong to the declared DEX payload.
  if (structureTokens[0]?.key === 'dexes' && structureTokens[1]?.key === 'align') {
    return [{ key: 'dex' }, { key: 'alignment' }, ...structureTokens.slice(2)];
  }
  return structureTokens;
};

const addField = (root: BuildNode, field: RawField, logicalPath = field.logical_path) => {
  const tokens = tokenizePath(logicalPath);
  if (tokens.length === 0) tokens.push({ key: 'field' });

  let node = root;
  for (const token of tokens) {
    const mapKey = token.index === undefined ? `p:${token.key}` : `i:${token.index}`;
    let child = node.childMap?.get(mapKey);
    if (!child) {
      child = newBuildNode(token.key, token.index);
      node.childMap?.set(mapKey, child);
      node.children.push(child);
    }
    node = child;
  }
  node.terminals?.push(field);
};

const compactValue = (field: RawField): unknown => {
  if (field.type === 'bytes' || field.type === 'padding' || Array.isArray(field.parsed_value)) {
    if (field.type === 'padding') return `${field.size.toLocaleString()} padding bytes`;
    return `${field.size.toLocaleString()} raw bytes`;
  }
  return field.parsed_value;
};

const semanticDescription = (key: string, parentKey?: string): string | undefined => {
  if (key === 'dex' && parentKey === 'verifier') {
    return 'Verifier dependency blocks grouped by DEX index.';
  }
  if (key === 'dex' && parentKey === 'typelookup') {
    return 'Type lookup tables grouped by DEX index.';
  }
  const descriptions: Record<string, string> = {
    vdex: 'Complete VDEX file mapped to physical byte ranges.',
    header: 'Fixed-layout file header fields.',
    sections: 'VDEX section directory records. Each record points to a separate payload range.',
    checksums: 'Location checksums for the DEX files in this VDEX.',
    dex: 'Embedded DEX files and their internal tables.',
    verifier: 'Verifier dependency data grouped by DEX and class.',
    typelookup: 'Type lookup hash tables grouped by DEX.',
    string_ids: 'DEX string identifier table.',
    type_ids: 'DEX type identifier table.',
    proto_ids: 'DEX prototype identifier table.',
    field_ids: 'DEX field identifier table.',
    method_ids: 'DEX method identifier table.',
    class_defs: 'DEX class definition table.',
    class_offsets: 'Verifier class offset table. The final entry is a terminal offset.',
    pair: 'Verifier assignability pairs encoded as destination/source ULEB128 values.',
    entry: 'Type lookup entries. Each entry contains string_offset and packed_data.',
    alignment: 'Alignment bytes between embedded DEX files.',
    padding: 'Padding and otherwise unmapped physical ranges.',
  };
  return descriptions[key];
};

const finishLeaf = (node: BuildNode, field: RawField, nodes: Map<number, BuildNode>) => {
  const isGap = field.type === 'padding' && field.description?.toLowerCase().includes('unmapped');
  node.kind = isGap ? 'gap' : 'field';
  node.offset = field.offset;
  node.span = field.size;
  node.covered_bytes = field.size;
  node.contiguous = true;
  node.field_count = 1;
  node.type = field.type;
  node.value = compactValue(field);
  node.description = field.description;
  node.preview_offset = field.offset;
  node.preview_span = field.size;
  delete node.terminals;
  delete node.childMap;
  nodes.set(node.id, node);
};

const sectionItemValue = (children: BuildNode[]): string | undefined => {
  const kindNode = children.find((child) => child.key === 'kind' && typeof child.value === 'number');
  if (!kindNode || typeof kindNode.value !== 'number') return undefined;
  const sectionNames: Record<number, string> = {
    0: 'Checksum section header',
    1: 'DEX file section header',
    2: 'Verifier deps section header',
    3: 'Type lookup section header',
  };
  return sectionNames[kindNode.value] ?? `Unknown section ${kindNode.value} header`;
};

const aggregateNode = (
  node: BuildNode,
  kind: StructureNodeKind,
  children: BuildNode[],
) => {
  children.sort((left, right) => (left.offset ?? 0) - (right.offset ?? 0) || left.id - right.id);
  const offset = children.reduce(
    (lowest, child) => Math.min(lowest, child.offset ?? Number.MAX_SAFE_INTEGER),
    Number.MAX_SAFE_INTEGER,
  );
  const end = children.reduce(
    (highest, child) => Math.max(highest, (child.offset ?? 0) + (child.span ?? 0)),
    0,
  );
  const observedOffset = offset === Number.MAX_SAFE_INTEGER ? node.declared_offset ?? 0 : offset;
  const coveredBytes = children.reduce((total, child) => total + (child.covered_bytes ?? 0), 0);
  const fieldCount = children.reduce((total, child) => total + (child.field_count ?? 0), 0);
  const firstChild = children.reduce<BuildNode | undefined>((first, child) => {
    if (!first) return child;
    return (child.preview_offset ?? child.offset ?? 0) < (first.preview_offset ?? first.offset ?? 0)
      ? child
      : first;
  }, undefined);

  node.kind = kind;
  node.children = children;
  node.offset = observedOffset;
  node.span = Math.max(0, end - observedOffset);
  node.covered_bytes = coveredBytes;
  node.contiguous = children.length === 0 || coveredBytes === end - observedOffset;
  node.field_count = fieldCount;
  node.preview_offset = firstChild?.preview_offset ?? firstChild?.offset ?? observedOffset;
  node.preview_span = firstChild?.preview_span ?? firstChild?.span ?? 0;
};

const makeRangeNode = (children: BuildNode[], nodes: Map<number, BuildNode>): BuildNode => {
  const start = children[0]?.index ?? 0;
  const finish = children.at(-1)?.index ?? start;
  const node = newBuildNode(`[${start}..${finish}]`);
  aggregateNode(node, 'range', children);
  node.item_count = children.length;
  node.description = `${children.length.toLocaleString()} array items with indices ${start.toLocaleString()} through ${finish.toLocaleString()}.`;
  delete node.terminals;
  delete node.childMap;
  nodes.set(node.id, node);
  return node;
};

const finishNode = (
  node: BuildNode,
  nodes: Map<number, BuildNode>,
  isRoot = false,
  parentKey?: string,
): BuildNode => {
  const terminals = node.terminals ?? [];
  if (terminals.length === 1 && node.children.length === 0) {
    finishLeaf(node, terminals[0], nodes);
    return node;
  }

  if (terminals.length > 0) {
    const duplicate = terminals.length > 1;
    for (let index = 0; index < terminals.length; index += 1) {
      const terminalNode = newBuildNode(duplicate ? `[${index}]` : 'value', duplicate ? index : undefined);
      terminalNode.terminals?.push(terminals[index]);
      node.children.push(terminalNode);
    }
  }

  let children = node.children.map((child) => finishNode(child, nodes, false, node.key));
  const indexedChildren = children
    .filter((child) => child.index !== undefined)
    .sort((left, right) => (left.index ?? 0) - (right.index ?? 0));
  const metadataChildren = children.filter((child) => child.index === undefined);
  const isArray = indexedChildren.length > 0;

  if (indexedChildren.length > ARRAY_CHUNK_SIZE) {
    const ranges: BuildNode[] = [];
    for (let start = 0; start < indexedChildren.length; start += ARRAY_CHUNK_SIZE) {
      ranges.push(makeRangeNode(indexedChildren.slice(start, start + ARRAY_CHUNK_SIZE), nodes));
    }
    children = [...ranges, ...metadataChildren];
  }

  const kind: StructureNodeKind = isRoot
    ? 'root'
    : node.index !== undefined
      ? 'item'
      : isArray
        ? 'array'
        : 'group';
  aggregateNode(node, kind, children);
  node.description = semanticDescription(node.key, parentKey);

  if (isArray) {
    node.item_count = indexedChildren.length;
    const firstSize = indexedChildren[0]?.span;
    if (
      firstSize !== undefined &&
      indexedChildren.every((child) => child.contiguous && child.span === firstSize)
    ) {
      node.item_size = firstSize;
    }
  } else if (node.index !== undefined) {
    node.value = sectionItemValue(children);
  }

  delete node.terminals;
  delete node.childMap;
  nodes.set(node.id, node);
  return node;
};

const readSectionDeclarations = (fields: RawField[]) => {
  const sections = new Map<number, { kind?: number; offset?: number; size?: number }>();
  const pattern = /^vdex\.sections\[(\d+)\]\.(kind|offset|size)$/;
  for (const field of fields) {
    const match = pattern.exec(field.logical_path);
    if (!match || typeof field.parsed_value !== 'number') continue;
    const index = Number(match[1]);
    const record = sections.get(index) ?? {};
    record[match[2] as 'kind' | 'offset' | 'size'] = field.parsed_value;
    sections.set(index, record);
  }

  const declarations = new Map<number, SectionDeclaration>();
  for (const record of sections.values()) {
    if (record.kind === undefined || declarations.has(record.kind)) continue;
    declarations.set(record.kind, { offset: record.offset, size: record.size });
  }
  return declarations;
};

const sectionKey = (kind: number): string => {
  const known: Record<number, string> = { 0: 'checksums', 1: 'dex', 2: 'verifier', 3: 'typelookup' };
  return known[kind] ?? `section_${kind}`;
};

const ensureSectionNodes = (root: BuildNode, declarations: Map<number, SectionDeclaration>) => {
  for (const [kind, declaration] of declarations) {
    const key = sectionKey(kind);
    const mapKey = `p:${key}`;
    let child = root.childMap?.get(mapKey);
    if (!child) {
      child = newBuildNode(key);
      root.childMap?.set(mapKey, child);
      root.children.push(child);
    }
    child.declared_offset = declaration.offset;
    child.declared_size = declaration.size;
  }
};

const sectionOwnedPath = (field: RawField, declarations: Map<number, SectionDeclaration>): string => {
  if (field.logical_path !== 'vdex.padding' || field.size === 0) return field.logical_path;
  const fieldEnd = field.offset + field.size;
  for (const [kind, declaration] of declarations) {
    const offset = declaration.offset;
    const size = declaration.size;
    if (offset === undefined || size === undefined || size === 0) continue;
    if (field.offset >= offset && fieldEnd <= offset + size) {
      return `vdex.${sectionKey(kind)}.padding`;
    }
  }
  return field.logical_path;
};

const serializeNode = (node: BuildNode): StructureNode => ({
  id: node.id,
  key: node.key,
  kind: node.kind ?? 'group',
  offset: node.offset ?? 0,
  span: node.span ?? 0,
  covered_bytes: node.covered_bytes ?? 0,
  contiguous: node.contiguous ?? true,
  field_count: node.field_count ?? 0,
  ...(node.index === undefined ? {} : { index: node.index }),
  ...(node.item_count === undefined ? {} : { item_count: node.item_count }),
  ...(node.item_size === undefined ? {} : { item_size: node.item_size }),
  ...(node.type === undefined ? {} : { type: node.type }),
  ...(node.value === undefined ? {} : { value: node.value }),
  ...(node.description === undefined ? {} : { description: node.description }),
  ...(node.declared_offset === undefined ? {} : { declared_offset: node.declared_offset }),
  ...(node.declared_size === undefined ? {} : { declared_size: node.declared_size }),
  preview_offset: node.preview_offset ?? node.offset ?? 0,
  preview_span: node.preview_span ?? node.span ?? 0,
  child_count: node.children.length,
});

const serializeChildren = (node: BuildNode): StructureChildren => ({
  node_id: node.id,
  children: node.children.map(serializeNode),
});

const buildStructureAnalysis = (parsedResult: Record<string, unknown>, fields: RawField[]) => {
  nextNodeId = 1;
  const mutableRoot = newBuildNode('vdex');
  const declarations = readSectionDeclarations(fields);
  for (const field of fields) addField(mutableRoot, field, sectionOwnedPath(field, declarations));
  ensureSectionNodes(mutableRoot, declarations);
  const nodes = new Map<number, BuildNode>();
  const root = finishNode(mutableRoot, nodes, true);
  const totalBytes = typeof parsedResult.total_bytes === 'number' ? parsedResult.total_bytes : 0;
  root.offset = 0;
  root.span = totalBytes;
  root.preview_offset = 0;
  root.preview_span = root.children[0]?.preview_span ?? 0;

  const initialChildren = [serializeChildren(root)];
  for (const child of root.children) {
    if (child.key === 'header' || child.key === 'sections') initialChildren.push(serializeChildren(child));
  }

  return { root, nodes, result: {
    total_bytes: totalBytes,
    field_count: fields.length,
    root: serializeNode(root),
    initial_children: initialChildren,
    unmapped_gaps: parsedResult.unmapped_gaps ?? [],
  } };
};

const nodeContainsOffset = (node: BuildNode, offset: number): boolean => {
  const rangeOffset = node.declared_offset ?? node.offset ?? 0;
  const rangeSize = node.declared_size ?? node.span ?? 0;
  return rangeSize > 0 && offset >= rangeOffset && offset < rangeOffset + rangeSize;
};

const findOffsetPath = (node: BuildNode, offset: number): BuildNode[] | null => {
  if (!nodeContainsOffset(node, offset)) return null;
  for (const child of node.children) {
    const path = findOffsetPath(child, offset);
    if (path) return [node, ...path];
  }
  return node.children.length === 0 || node.declared_size !== undefined ? [node] : null;
};

const requireActiveAnalysis = (analysisId: number) => {
  if (!activeAnalysis || activeAnalysis.requestId !== analysisId) {
    throw new Error('The requested analysis is no longer active');
  }
  return activeAnalysis;
};

const sendChildren = (message: Extract<WorkerRequest, { type: 'children' }>) => {
  const analysis = requireActiveAnalysis(message.analysisId);
  const node = analysis.nodes.get(message.nodeId);
  if (!node) throw new Error(`Unknown tree node ${message.nodeId}`);
  scope.postMessage({
    type: 'children',
    requestId: message.requestId,
    analysisId: message.analysisId,
    nodeId: node.id,
    children: node.children.map(serializeNode),
  });
};

const sendOffsetPath = (message: Extract<WorkerRequest, { type: 'find-offset' }>) => {
  const analysis = requireActiveAnalysis(message.analysisId);
  const path = findOffsetPath(analysis.root, message.offset) ?? [];
  scope.postMessage({
    type: 'offset-path',
    requestId: message.requestId,
    analysisId: message.analysisId,
    path: path.map(serializeNode),
    branches: path.slice(0, -1).map(serializeChildren),
  });
};

const analyze = async (requestId: number, buffer: ArrayBuffer) => {
  activeAnalysis = null;
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
  const parsedResult = typeof result === 'string' ? JSON.parse(result) as unknown : result;
  const analysisMs = performance.now() - startedAt;
  const fields =
    typeof parsedResult === 'object' && parsedResult !== null &&
    Array.isArray((parsedResult as { fields?: unknown }).fields)
      ? (parsedResult as { fields: RawField[] }).fields
      : null;

  if (!fields) {
    scope.postMessage({
      type: 'result',
      requestId,
      result: parsedResult,
      sourceBuffer: buffer,
      analysisMs,
      treeMs: 0,
    }, [buffer]);
    return;
  }

  scope.postMessage({
    type: 'progress',
    requestId,
    stage: 'preparing',
    label: 'Building semantic byte tree',
    detail: `Grouping ${fields.length.toLocaleString()} fields into headers and arrays`,
    percent: 92,
  });

  const treeStartedAt = performance.now();
  const structure = buildStructureAnalysis(parsedResult as Record<string, unknown>, fields);
  activeAnalysis = { requestId, root: structure.root, nodes: structure.nodes };
  const treeMs = performance.now() - treeStartedAt;
  scope.postMessage({
    type: 'result',
    requestId,
    result: structure.result,
    sourceBuffer: buffer,
    analysisMs,
    treeMs,
  }, [buffer]);
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

  if (message.type === 'children' || message.type === 'find-offset') {
    try {
      if (message.type === 'children') sendChildren(message);
      else sendOffsetPath(message);
    } catch (error: unknown) {
      scope.postMessage({
        type: 'error',
        requestId: message.requestId,
        message: messageFromError(error),
      });
    }
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
