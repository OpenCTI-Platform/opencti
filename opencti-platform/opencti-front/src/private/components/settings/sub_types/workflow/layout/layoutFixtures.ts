import type { XYPosition } from 'reactflow';
import type { LayoutInputEdge, LayoutInputNode } from './types';

// Test fixtures for the workflow layout: sample workflows, a seeded random generator and
// geometry checks. Elements are built like useWorkflowInitialElements + usePlaceholdersSync.

export interface WorkflowFixture {
  name: string;
  statuses: string[];
  transitions: [string[], string, string | null][]; // [from, event, to]
}

export const SAMPLES: Record<'review' | 'incident' | 'rfi' | 'case', WorkflowFixture> = {
  review: {
    name: 'Report review',
    statuses: ['NEW', 'IN_REVIEW', 'ANALYZED', 'CLOSED'],
    transitions: [
      [['NEW'], 'submit', 'IN_REVIEW'],
      [['IN_REVIEW'], 'approve', 'ANALYZED'],
      [['IN_REVIEW'], 'reject', 'NEW'],
      [['ANALYZED'], 'close', 'CLOSED'],
      [['ANALYZED'], 'reopen', 'IN_REVIEW'],
    ],
  },
  incident: {
    name: 'Incident response',
    statuses: ['NEW', 'TRIAGED', 'ESCALATED', 'CONTAINMENT', 'RESOLVED', 'CLOSED'],
    transitions: [
      [['NEW'], 'triage', 'TRIAGED'],
      [['TRIAGED'], 'escalate', 'ESCALATED'],
      [['TRIAGED'], 'contain', 'CONTAINMENT'],
      [['ESCALATED'], 'contain', 'CONTAINMENT'],
      [['TRIAGED'], 'false_positive', 'CLOSED'],
      [['CONTAINMENT'], 'resolve', 'RESOLVED'],
      [['RESOLVED'], 'close', 'CLOSED'],
      [['RESOLVED'], 'reopen', 'TRIAGED'],
    ],
  },
  rfi: {
    name: 'Request for information',
    statuses: ['DRAFT', 'PENDING', 'IN_PROGRESS', 'BLOCKED', 'DONE', 'CANCELLED'],
    transitions: [
      [['DRAFT'], 'send', 'PENDING'],
      [['PENDING'], 'accept', 'IN_PROGRESS'],
      [['IN_PROGRESS'], 'block', 'BLOCKED'],
      [['BLOCKED'], 'unblock', 'IN_PROGRESS'],
      [['IN_PROGRESS'], 'add_note', 'IN_PROGRESS'],
      [['IN_PROGRESS'], 'answer', 'DONE'],
      [['DRAFT', 'PENDING', 'IN_PROGRESS', 'BLOCKED'], 'cancel', 'CANCELLED'],
      [['DONE'], 'archive', null],
    ],
  },
  case: {
    name: 'Case management',
    statuses: ['OPEN', 'QUALIFIED', 'ASSIGNED', 'INVESTIGATING', 'WAITING_CUSTOMER', 'REMEDIATION', 'VALIDATION', 'RESOLVED', 'CLOSED', 'IMPORTED'],
    transitions: [
      [['OPEN'], 'qualify', 'QUALIFIED'],
      [['QUALIFIED'], 'assign', 'ASSIGNED'],
      [['ASSIGNED'], 'start', 'INVESTIGATING'],
      [['INVESTIGATING'], 'ask_customer', 'WAITING_CUSTOMER'],
      [['WAITING_CUSTOMER'], 'reply', 'INVESTIGATING'],
      [['INVESTIGATING'], 'remediate', 'REMEDIATION'],
      [['REMEDIATION'], 'validate', 'VALIDATION'],
      [['VALIDATION'], 'fail', 'REMEDIATION'],
      [['VALIDATION'], 'pass', 'RESOLVED'],
      [['INVESTIGATING'], 'no_action', 'RESOLVED'],
      [['RESOLVED'], 'close', 'CLOSED'],
      [['CLOSED'], 'reopen', 'QUALIFIED'],
      [['ASSIGNED'], 'unassign', 'QUALIFIED'],
      [['QUALIFIED'], 'duplicate', 'CLOSED'],
      [['IMPORTED'], 'review', 'QUALIFIED'],
      [['RESOLVED'], 'reinvestigate', 'INVESTIGATING'],
    ],
  },
};

export const transitionId = (from: string[], event: string, to: string | null) => `transition-${from.join(',')}-${event}-${to ?? '_unlinked'}`;

export const buildElements = (fixture: WorkflowFixture): { nodes: LayoutInputNode[]; edges: LayoutInputEdge[] } => {
  const nodes: LayoutInputNode[] = fixture.statuses.map((id) => ({ id, type: 'status', width: 160, height: 50 }));
  const edges: LayoutInputEdge[] = [];
  fixture.transitions.forEach(([from, event, to]) => {
    const id = transitionId(from, event, to);
    nodes.push({ id, type: 'transition', width: 160, height: 50 });
    from.forEach((f) => edges.push({ id: `e-${f}->${id}`, source: f, target: id }));
    if (to) edges.push({ id: `e-${id}->${to}`, source: id, target: to });
  });
  const transitionIds = new Set(nodes.filter((n) => n.type === 'transition').map((n) => n.id));
  fixture.statuses.forEach((status) => {
    if (!edges.some((e) => e.source === status && transitionIds.has(e.target))) {
      const id = `placeholder-${status}`;
      nodes.push({ id, type: 'placeholder', width: 160, height: 50 });
      edges.push({ id: `e-${status}->${id}`, source: status, target: id });
    }
  });
  return { nodes, edges };
};

// Seeded random workflow: a spanning chain, skip-ahead and backward transitions, and one
// multi-source transition.
export const randomWorkflow = (seed: number, size?: number): WorkflowFixture => {
  let s = seed >>> 0 || 1;
  const rnd = () => {
    s = (s * 1664525 + 1013904223) >>> 0;
    return s / 4294967296;
  };
  const n = size ?? 6 + Math.floor(rnd() * 8);
  const statuses = Array.from({ length: n }, (_, i) => `STATUS_${String.fromCharCode(65 + (i % 26))}${i >= 26 ? i : ''}`);
  const transitions: WorkflowFixture['transitions'] = [];
  const keys = new Set<string>();
  const add = (from: string[], event: string, to: string) => {
    const key = transitionId(from, event, to);
    if (!keys.has(key)) {
      keys.add(key);
      transitions.push([from, event, to]);
    }
  };
  for (let i = 1; i < n; i += 1) add([statuses[Math.floor(rnd() * i)]], `go_${i}`, statuses[i]);
  for (let k = 0; k < Math.floor(n * 0.6); k += 1) {
    const a = Math.floor(rnd() * n);
    const b = Math.floor(rnd() * n);
    if (a !== b) add([statuses[a]], a < b ? `skip_${k}` : `back_${k}`, statuses[b]);
  }
  if (n > 4) add([statuses[1], statuses[2], statuses[3]], 'cancel', statuses[n - 1]);
  return { name: `random-${seed}`, statuses, transitions };
};

export interface Box {
  id: string;
  x: number;
  y: number;
  w: number;
  h: number;
}

export const boxesOverlap = (a: Box, b: Box) => a.x < b.x + b.w - 1 && b.x < a.x + a.w - 1 && a.y < b.y + b.h - 1 && b.y < a.y + a.h - 1;

// True when an axis-aligned segment enters the inside of the box (2px tolerance at the border).
export const segmentHitsBox = (p: XYPosition, q: XYPosition, b: Box) => {
  const pad = 2;
  return Math.max(p.x, q.x) > b.x + pad && Math.min(p.x, q.x) < b.x + b.w - pad
    && Math.max(p.y, q.y) > b.y + pad && Math.min(p.y, q.y) < b.y + b.h - pad;
};

export const isAxisAligned = (points: XYPosition[]) => points.slice(1)
  .every((q, i) => Math.abs(q.x - points[i].x) < 0.01 || Math.abs(q.y - points[i].y) < 0.01);

export const countBends = (routes: Map<string, XYPosition[]>) => [...routes.values()].reduce((sum, r) => sum + Math.max(0, r.length - 2), 0);
