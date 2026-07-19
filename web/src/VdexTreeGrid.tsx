import { useEffect, useMemo, useRef, useState } from 'react';
import {
  ChevronDown,
  ChevronRight,
  ChevronsDownUp,
  CornerDownRight,
  ListTree,
  Search,
} from 'lucide-react';

import type { StructureChildren, StructureNode } from './worker-protocol';

interface VdexTreeGridProps {
  root: StructureNode;
  initialChildren: StructureChildren[];
  sourceBytes: Uint8Array;
  loadChildren: (nodeId: number) => Promise<StructureNode[]>;
  findOffset: (offset: number) => Promise<{ path: StructureNode[]; branches: StructureChildren[] }>;
}

interface VisibleRow {
  node: StructureNode;
  depth: number;
  path: string;
  logicalIndex: number;
  parentId?: number;
}

interface Selection {
  node: StructureNode;
  path: string;
}

interface PhysicalRange {
  offset: number;
  span: number;
}

interface VisibleWindow {
  rows: VisibleRow[];
  previousRow?: VisibleRow;
  nextRow?: VisibleRow;
  windowed: boolean;
}

interface FlatTree {
  rows: VisibleRow[];
  indexById: Map<number, number>;
}

const HEX_PREVIEW_BYTES = 16;
const INSPECTOR_BYTES = 256;
const MAX_VISIBLE_ROWS = 2048;
const ROWS_BEFORE_FOCUS = 512;

const TOP_LEVEL_LABELS: Record<string, string> = {
  vdex: 'VDEX file',
  header: 'VDEX file header',
  sections: 'Section header table',
  checksums: 'Checksum section',
  dex: 'DEX file section',
  verifier: 'Verifier deps section',
  typelookup: 'Type lookup section',
  dexes: 'DEX alignment ranges',
  padding: 'Padding / unmapped ranges',
};

const toHex = (value: number, padding = 8): string =>
  value.toString(16).padStart(padding, '0').toUpperCase();

const formatBytes = (bytes: number): string => {
  if (bytes < 1024) return `${bytes.toLocaleString()} B`;
  const units = ['KB', 'MB', 'GB'];
  let value = bytes / 1024;
  let unit = units[0];
  for (let index = 1; index < units.length && value >= 1024; index += 1) {
    value /= 1024;
    unit = units[index];
  }
  return `${value.toFixed(value >= 100 ? 0 : value >= 10 ? 1 : 2)} ${unit}`;
};

const formatValue = (value: unknown): string => {
  if (typeof value === 'string') return JSON.stringify(value);
  if (value === null) return 'null';
  if (value === undefined) return '';
  if (typeof value === 'object') return JSON.stringify(value) ?? String(value);
  return String(value);
};

const getNodeLabel = (node: StructureNode, depth: number): string => {
  if (node.kind === 'root' || depth === 1) return TOP_LEVEL_LABELS[node.key] ?? node.key;
  return node.key;
};

const getNodeValue = (node: StructureNode): string => {
  if (node.value !== undefined) return formatValue(node.value);
  if (node.kind === 'range') return `${node.item_count?.toLocaleString() ?? 0} array items`;
  if (node.kind === 'array') {
    const itemCount = node.item_count?.toLocaleString() ?? 0;
    const itemSize = node.item_size === undefined ? '' : ` · ${formatBytes(node.item_size)}/item`;
    const mapped = node.declared_size !== undefined && node.covered_bytes !== node.declared_size
      ? ` · ${node.covered_bytes.toLocaleString()} B mapped`
      : '';
    return `${itemCount} items · ${node.field_count.toLocaleString()} fields${itemSize}${mapped}`;
  }
  if (node.kind === 'item') return `${node.field_count.toLocaleString()} fields`;
  const mapped = node.declared_size !== undefined && node.covered_bytes !== node.declared_size
    ? ` · ${node.covered_bytes.toLocaleString()} B mapped`
    : '';
  return `${node.field_count.toLocaleString()} fields${mapped}`;
};

const getNodeSize = (node: StructureNode): string => {
  if (node.declared_size !== undefined) return formatBytes(node.declared_size);
  if (node.contiguous) return formatBytes(node.span);
  return `${formatBytes(node.covered_bytes)} / ${formatBytes(node.span)} span`;
};

const displayRange = (node: StructureNode): PhysicalRange => {
  if (node.declared_offset !== undefined && node.declared_size !== undefined) {
    return { offset: node.declared_offset, span: node.declared_size };
  }
  if (!node.contiguous) return { offset: node.preview_offset, span: node.preview_span };
  return { offset: node.offset, span: node.span };
};

const getHexPreview = (sourceBytes: Uint8Array, node: StructureNode): string => {
  const range = displayRange(node);
  if (range.span === 0 || range.offset >= sourceBytes.length) return '-';
  const end = Math.min(sourceBytes.length, range.offset + range.span, range.offset + HEX_PREVIEW_BYTES);
  const bytes = sourceBytes.subarray(range.offset, end);
  const preview = Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0').toUpperCase()).join(' ');
  return end < range.offset + range.span ? `${preview} ...` : preview;
};

const childPath = (parentPath: string, node: StructureNode): string => {
  if (node.kind === 'root') return 'vdex';
  if (node.kind === 'range') return `${parentPath}${node.key}`;
  if (node.index !== undefined) return `${parentPath}[${node.index}]`;
  return `${parentPath}.${node.key}`;
};

const childrenMapFrom = (batches: StructureChildren[]): Map<number, StructureNode[]> =>
  new Map(batches.map((batch) => [batch.node_id, batch.children]));

const cachedBranchIds = (
  childrenById: ReadonlyMap<number, StructureNode[]>,
  nodeId: number,
): Set<number> => {
  const ids = new Set<number>([nodeId]);
  const pending = [...(childrenById.get(nodeId) ?? [])];
  for (let index = 0; index < pending.length; index += 1) {
    const child = pending[index];
    ids.add(child.id);
    pending.push(...(childrenById.get(child.id) ?? []));
  }
  return ids;
};

const flattenExpanded = (
  root: StructureNode,
  expanded: ReadonlySet<number>,
  childrenById: ReadonlyMap<number, StructureNode[]>,
): FlatTree => {
  const rows: VisibleRow[] = [];
  const indexById = new Map<number, number>();
  const walk = (node: StructureNode, depth: number, parentPath: string, parentId?: number) => {
    const path = childPath(parentPath, node);
    const logicalIndex = rows.length;
    rows.push({ node, depth, path, logicalIndex, parentId });
    indexById.set(node.id, logicalIndex);
    if (!expanded.has(node.id)) return;

    const descendantParentPath = node.kind === 'range' ? parentPath : path;
    for (const child of childrenById.get(node.id) ?? []) {
      walk(child, depth + 1, descendantParentPath, node.id);
    }
  };
  walk(root, 0, '');
  return { rows, indexById };
};

const visibleWindow = (tree: FlatTree, anchorId: number): VisibleWindow => {
  const anchorIndex = tree.indexById.get(anchorId) ?? 0;
  const start = Math.max(0, anchorIndex - ROWS_BEFORE_FOCUS);
  const end = Math.min(tree.rows.length, start + MAX_VISIBLE_ROWS);
  return {
    rows: tree.rows.slice(start, end),
    previousRow: start > 0 ? tree.rows[start - 1] : undefined,
    nextRow: end < tree.rows.length ? tree.rows[end] : undefined,
    windowed: start > 0 || end < tree.rows.length,
  };
};

const defaultExpandedNodes = (
  root: StructureNode,
  childrenById: ReadonlyMap<number, StructureNode[]>,
): Set<number> => {
  const expanded = new Set<number>([root.id]);
  for (const child of childrenById.get(root.id) ?? []) {
    if (child.key === 'header' || child.key === 'sections') expanded.add(child.id);
  }
  return expanded;
};

const buildHexDump = (sourceBytes: Uint8Array, node: StructureNode): string => {
  const range = displayRange(node);
  if (range.span === 0 || range.offset >= sourceBytes.length) return 'No bytes in this range.';
  const end = Math.min(sourceBytes.length, range.offset + range.span, range.offset + INSPECTOR_BYTES);
  const lines: string[] = [];
  for (let offset = range.offset; offset < end; offset += 16) {
    const row = sourceBytes.subarray(offset, Math.min(offset + 16, end));
    const hex = Array.from(row, (byte) => byte.toString(16).padStart(2, '0').toUpperCase())
      .join(' ')
      .padEnd(47, ' ');
    const ascii = Array.from(row, (byte) => byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : '.')
      .join('');
    lines.push(`${toHex(offset)}  ${hex}  ${ascii}`);
  }
  return lines.join('\n');
};

export default function VdexTreeGrid({
  root,
  initialChildren,
  sourceBytes,
  loadChildren,
  findOffset,
}: VdexTreeGridProps) {
  const [childrenById, setChildrenById] = useState<Map<number, StructureNode[]>>(
    () => childrenMapFrom(initialChildren),
  );
  const [expanded, setExpanded] = useState<Set<number>>(
    () => defaultExpandedNodes(root, childrenMapFrom(initialChildren)),
  );
  const [selection, setSelection] = useState<Selection>({ node: root, path: 'vdex' });
  const [focusedId, setFocusedId] = useState(root.id);
  const [loadingNodes, setLoadingNodes] = useState<Set<number>>(new Set());
  const [offsetInput, setOffsetInput] = useState('');
  const [offsetError, setOffsetError] = useState('');
  const [treeError, setTreeError] = useState('');
  const gridRef = useRef<HTMLDivElement | null>(null);
  const treeScrollRef = useRef<HTMLDivElement | null>(null);
  const interactionGenerationRef = useRef(0);

  useEffect(() => {
    interactionGenerationRef.current += 1;
    const nextChildren = childrenMapFrom(initialChildren);
    setChildrenById(nextChildren);
    setExpanded(defaultExpandedNodes(root, nextChildren));
    setSelection({ node: root, path: 'vdex' });
    setFocusedId(root.id);
    setLoadingNodes(new Set());
    setOffsetInput('');
    setOffsetError('');
    setTreeError('');
  }, [initialChildren, root]);

  useEffect(() => {
    const mobile = window.matchMedia('(max-width: 760px)');
    const revealKeyColumn = () => {
      const scroller = treeScrollRef.current;
      if (!mobile.matches || !scroller) return;
      const headers = scroller.querySelectorAll<HTMLElement>('[role="columnheader"]');
      const offsetHeader = headers[0];
      const keyHeader = headers[3];
      if (offsetHeader && keyHeader) scroller.scrollLeft = keyHeader.offsetLeft - offsetHeader.offsetWidth;
    };
    revealKeyColumn();
    mobile.addEventListener('change', revealKeyColumn);
    return () => mobile.removeEventListener('change', revealKeyColumn);
  }, [root]);

  const flatTree = useMemo(
    () => flattenExpanded(root, expanded, childrenById),
    [root, expanded, childrenById],
  );
  const visible = useMemo(() => visibleWindow(flatTree, focusedId), [flatTree, focusedId]);
  const rows = visible.rows;
  const selectedHexDump = useMemo(
    () => buildHexDump(sourceBytes, selection.node),
    [selection, sourceBytes],
  );

  const toggleNode = async (node: StructureNode) => {
    if (node.child_count === 0 || loadingNodes.has(node.id)) return;
    setFocusedId(node.id);
    if (expanded.has(node.id)) {
      interactionGenerationRef.current += 1;
      const branchIds = cachedBranchIds(childrenById, node.id);
      setExpanded((current) => {
        const next = new Set(current);
        for (const id of branchIds) next.delete(id);
        return next;
      });
      setChildrenById((current) => {
        const next = new Map(current);
        for (const id of branchIds) next.delete(id);
        return next;
      });
      return;
    }

    const generation = interactionGenerationRef.current;
    setLoadingNodes((current) => new Set(current).add(node.id));
    try {
      const children = childrenById.get(node.id) ?? await loadChildren(node.id);
      if (generation !== interactionGenerationRef.current) return;
      setChildrenById((current) => new Map(current).set(node.id, children));
      setExpanded((current) => new Set(current).add(node.id));
      setTreeError('');
    } catch (caught) {
      setTreeError(caught instanceof Error ? caught.message : 'Failed to load this tree block.');
    } finally {
      setLoadingNodes((current) => {
        const next = new Set(current);
        next.delete(node.id);
        return next;
      });
    }
  };

  const focusRow = (nodeId: number) => {
    setFocusedId(nodeId);
    window.requestAnimationFrame(() => {
      gridRef.current?.querySelector<HTMLElement>(`[data-node-id="${nodeId}"]`)?.focus();
    });
  };

  const onRowKeyDown = (event: React.KeyboardEvent, row: VisibleRow, rowIndex: number) => {
    if (event.target !== event.currentTarget) return;
    if (event.key === 'ArrowDown' && (rowIndex < rows.length - 1 || visible.nextRow)) {
      event.preventDefault();
      focusRow(rows[rowIndex + 1]?.node.id ?? visible.nextRow?.node.id ?? row.node.id);
    } else if (event.key === 'ArrowUp' && (rowIndex > 0 || visible.previousRow)) {
      event.preventDefault();
      focusRow(rows[rowIndex - 1]?.node.id ?? visible.previousRow?.node.id ?? row.node.id);
    } else if (event.key === 'ArrowRight' && row.node.child_count > 0) {
      event.preventDefault();
      if (!expanded.has(row.node.id)) void toggleNode(row.node);
      else if (rows[rowIndex + 1]) focusRow(rows[rowIndex + 1].node.id);
    } else if (event.key === 'ArrowLeft') {
      event.preventDefault();
      if (expanded.has(row.node.id)) void toggleNode(row.node);
      else if (row.parentId !== undefined) focusRow(row.parentId);
    } else if (event.key === 'Home') {
      event.preventDefault();
      focusRow(root.id);
    } else if (event.key === 'End') {
      event.preventDefault();
      focusRow(flatTree.rows.at(-1)?.node.id ?? root.id);
    } else if (event.key === 'Enter') {
      event.preventDefault();
      setSelection({ node: row.node, path: row.path });
    }
  };

  const jumpToOffset = async (event: React.FormEvent) => {
    event.preventDefault();
    const trimmed = offsetInput.trim();
    const parsed = /^0x[0-9a-f]+$/i.test(trimmed)
      ? Number.parseInt(trimmed.slice(2), 16)
      : /^\d+$/.test(trimmed)
        ? Number.parseInt(trimmed, 10)
        : Number.NaN;
    if (!Number.isSafeInteger(parsed) || parsed < 0 || parsed >= sourceBytes.length) {
      setOffsetError(`Enter an offset from 0 to 0x${toHex(Math.max(0, sourceBytes.length - 1))}.`);
      return;
    }

    const generation = interactionGenerationRef.current + 1;
    interactionGenerationRef.current = generation;
    try {
      const { path, branches } = await findOffset(parsed);
      if (generation !== interactionGenerationRef.current) return;
      const leaf = path.at(-1);
      if (!leaf) {
        setOffsetError(`No parsed field covers offset 0x${toHex(parsed)}.`);
        return;
      }

      const nextChildren = childrenMapFrom([...initialChildren, ...branches]);
      const nextExpanded = defaultExpandedNodes(root, nextChildren);
      for (const ancestor of path.slice(0, -1)) nextExpanded.add(ancestor.id);
      setChildrenById(nextChildren);
      setExpanded(nextExpanded);
      const logicalPath = path.reduce((current, item) => {
        if (item.kind === 'root') return 'vdex';
        if (item.kind === 'range') return current;
        return childPath(current, item);
      }, '');
      setOffsetError('');
      setSelection({ node: leaf, path: logicalPath });
      setFocusedId(leaf.id);
      window.setTimeout(() => {
        gridRef.current
          ?.querySelector<HTMLElement>(`[data-node-id="${leaf.id}"]`)
          ?.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }, 0);
    } catch (caught) {
      setOffsetError(caught instanceof Error ? caught.message : 'Failed to find this byte offset.');
    }
  };

  const node = selection.node;
  const selectedRange = displayRange(node);
  const previewEnd = Math.min(
    sourceBytes.length,
    selectedRange.offset + selectedRange.span,
    selectedRange.offset + INSPECTOR_BYTES,
  );
  const isInspectorTruncated = previewEnd < selectedRange.offset + selectedRange.span;

  return (
    <section className="structure-section" aria-labelledby="structure-title">
      <div className="structure-toolbar">
        <div className="structure-title-group">
          <h2 id="structure-title"><ListTree size={19} /> Byte structure</h2>
          <span title={visible.windowed ? `Showing up to ${MAX_VISIBLE_ROWS.toLocaleString()} rows around the focused tree item.` : undefined}>
            {rows.length.toLocaleString()} {visible.windowed ? 'windowed' : 'visible'} · {root.field_count.toLocaleString()} fields
          </span>
        </div>

        <div className="tree-actions">
          <form className="offset-search" onSubmit={jumpToOffset}>
            <label htmlFor="offset-input">Go to offset</label>
            <input
              id="offset-input"
              value={offsetInput}
              onChange={(event) => setOffsetInput(event.target.value)}
              placeholder="0x00000000"
              spellCheck={false}
              aria-invalid={offsetError ? true : undefined}
              aria-describedby={offsetError ? 'offset-error' : undefined}
            />
            <button type="submit" className="icon-button" title="Go to byte offset" aria-label="Go to byte offset">
              <Search size={17} />
            </button>
          </form>
          <button
            type="button"
            className="icon-button"
            onClick={() => {
              interactionGenerationRef.current += 1;
              const nextChildren = childrenMapFrom(initialChildren);
              setChildrenById(nextChildren);
              setExpanded(new Set([root.id]));
              focusRow(root.id);
            }}
            title="Collapse all blocks"
            aria-label="Collapse all blocks"
          >
            <ChevronsDownUp size={18} />
          </button>
          <button
            type="button"
            className="icon-button"
            onClick={() => {
              interactionGenerationRef.current += 1;
              const nextChildren = childrenMapFrom(initialChildren);
              setChildrenById(nextChildren);
              setExpanded(defaultExpandedNodes(root, nextChildren));
              focusRow(root.id);
            }}
            title="Restore header view"
            aria-label="Restore header view"
          >
            <CornerDownRight size={18} />
          </button>
        </div>
      </div>
      {offsetError && <p id="offset-error" className="offset-error" role="alert">{offsetError}</p>}
      {treeError && <p className="tree-error" role="alert">{treeError}</p>}
      <p className="visually-hidden" aria-live="polite" aria-atomic="true">
        Selected {selection.path}, offset 0x{toHex(selectedRange.offset)}, size {getNodeSize(node)}.
      </p>

      <div className="structure-workspace">
        <div ref={treeScrollRef} className="tree-scroll">
          <div
            ref={gridRef}
            className="tree-grid"
            role="treegrid"
            aria-label="VDEX byte structure"
            aria-rowcount={visible.windowed ? -1 : flatTree.rows.length + 1}
          >
            <div className="tree-grid-header" role="row" aria-rowindex={1}>
              <span role="columnheader">Offset</span>
              <span role="columnheader">Hex bytes</span>
              <span role="columnheader">Size</span>
              <span role="columnheader">Key</span>
              <span role="columnheader">Value</span>
            </div>

            {rows.map((row, rowIndex) => {
              const hasChildren = row.node.child_count > 0;
              const isExpanded = expanded.has(row.node.id);
              const isLoading = loadingNodes.has(row.node.id);
              const isSelected = selection.node.id === row.node.id;
              const fragmented = row.node.declared_size === undefined && !row.node.contiguous;
              const rowOffset = row.node.declared_offset ?? row.node.offset;
              const sizeTitle = row.node.declared_size !== undefined
                ? `Declared ${row.node.declared_size.toLocaleString()} bytes; ${row.node.covered_bytes.toLocaleString()} bytes mapped.`
                : fragmented
                  ? `${formatBytes(row.node.covered_bytes)} mapped inside a ${formatBytes(row.node.span)} physical span.`
                  : undefined;
              return (
                <div
                  key={row.node.id}
                  className={`tree-row node-${row.node.kind}${isSelected ? ' selected' : ''}`}
                  role="row"
                  aria-rowindex={row.logicalIndex + 2}
                  aria-level={row.depth + 1}
                  aria-expanded={hasChildren ? isExpanded : undefined}
                  aria-busy={isLoading || undefined}
                  aria-selected={isSelected}
                  data-node-id={row.node.id}
                  data-node-path={row.path}
                  tabIndex={focusedId === row.node.id ? 0 : -1}
                  onFocus={() => setFocusedId(row.node.id)}
                  onKeyDown={(event) => onRowKeyDown(event, row, rowIndex)}
                  onClick={(event) => {
                    setFocusedId(row.node.id);
                    event.currentTarget.focus();
                    setSelection({ node: row.node, path: row.path });
                  }}
                >
                  <span className="offset-cell" role="gridcell">0x{toHex(rowOffset)}</span>
                  <span
                    className="hex-cell"
                    role="gridcell"
                    title={fragmented ? 'Preview contains only the first mapped field of this fragmented group.' : undefined}
                  >
                    {getHexPreview(sourceBytes, row.node)}
                  </span>
                  <span
                    className={`size-cell${fragmented ? ' fragmented' : ''}`}
                    role="gridcell"
                    title={sizeTitle}
                  >
                    {getNodeSize(row.node)}
                  </span>
                  <span className="key-cell" role="gridcell" style={{ '--tree-depth': row.depth } as React.CSSProperties}>
                    {hasChildren ? (
                      <button
                        type="button"
                        className="disclosure-button"
                        tabIndex={-1}
                        onClick={(event) => { event.stopPropagation(); void toggleNode(row.node); }}
                        disabled={isLoading}
                        aria-label={`${isExpanded ? 'Collapse' : 'Expand'} ${getNodeLabel(row.node, row.depth)}`}
                        title={`${isExpanded ? 'Collapse' : 'Expand'} ${getNodeLabel(row.node, row.depth)}`}
                      >
                        {isExpanded ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                      </button>
                    ) : <span className="disclosure-spacer" />}
                    <span className="key-label">{getNodeLabel(row.node, row.depth)}</span>
                    <span className="node-kind">{row.node.kind}</span>
                  </span>
                  <span className="value-cell" role="gridcell" title={getNodeValue(row.node)}>
                    {getNodeValue(row.node)}
                  </span>
                </div>
              );
            })}
          </div>
        </div>

        <aside className="byte-inspector" aria-label="Selected byte range">
          <div className="inspector-heading">
            <div>
              <span className="eyebrow">Selected range</span>
              <h3>{getNodeLabel(node, selection.path === 'vdex' ? 0 : 2)}</h3>
            </div>
            <span className={`range-state${node.declared_size === undefined && !node.contiguous ? ' fragmented' : ''}`}>
              {node.declared_size !== undefined ? 'declared block' : node.contiguous ? 'contiguous' : 'fragmented'}
            </span>
          </div>

          <dl className="inspector-meta">
            <div><dt>Path</dt><dd>{selection.path}</dd></div>
            <div><dt>Offset</dt><dd>0x{toHex(selectedRange.offset)}</dd></div>
            <div><dt>Size</dt><dd>{getNodeSize(node)}</dd></div>
            <div><dt>Type</dt><dd>{node.type ?? node.kind}</dd></div>
            {node.declared_size !== undefined && node.covered_bytes !== node.declared_size && (
              <div><dt>Mapped bytes</dt><dd>{node.covered_bytes.toLocaleString()} B</dd></div>
            )}
          </dl>

          <div className="inspector-value">
            <span className="eyebrow">Value</span>
            <code>{getNodeValue(node)}</code>
          </div>
          {node.description && <p className="inspector-description">{node.description}</p>}

          <div className="hex-dump-heading">
            <span className="eyebrow">
              {node.declared_size !== undefined ? 'Declared section bytes' : node.contiguous ? 'Physical bytes' : 'First mapped field'}
            </span>
            <span>{Math.max(0, previewEnd - selectedRange.offset).toLocaleString()} shown</span>
          </div>
          <pre className="hex-dump">{selectedHexDump}</pre>
          {isInspectorTruncated && (
            <p className="hex-truncated">Showing the first {INSPECTOR_BYTES} bytes of this physical span.</p>
          )}
          {!node.contiguous && node.declared_size === undefined && (
            <p className="hex-truncated">This group is fragmented. Its child rows identify the remaining mapped ranges.</p>
          )}
        </aside>
      </div>
    </section>
  );
}
