/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import type { Edge, Node, XYPosition } from 'reactflow';
import type { PlaybookDefinitionEdge } from '../types/playbook-types';
import { toDefinitionLinks } from './playbookRewiring';

// Undo / redo of the editor session through inverse operations: every change made on the canvas
// is recorded with the operation that cancels it, both expressed with the existing playbook
// mutations (add, delete, replace, relink, move). Nothing is restored by overwriting the whole
// definition, so the server checks every step (one entry point, no cycle, every step reachable).
// A change without an exact inverse (a step deleted with its branch, a step inserted on a link,
// a component replaced by one with fewer outputs) ends the history: it is not undoable, and the
// steps recorded before it are dropped so an undo never applies to a playbook it was not made on.

export interface PlaybookStepSpec {
  component_id: string;
  name: string;
  configuration: string | null;
  description?: string;
  position: XYPosition;
}

interface AddOperation { kind: 'add'; nodeId: string; node: PlaybookStepSpec; parentNodeId?: string; parentPortId?: string }
interface DeleteOperation { kind: 'delete'; nodeId: string }
interface ReplaceOperation { kind: 'replace'; nodeId: string; node: PlaybookStepSpec }
interface RelinkOperation { kind: 'relink'; linkId: string; toNodeId: string; fromNodeId: string; fromPortId: string }
interface MoveOperation { kind: 'move'; nodeId: string; parentNodeId: string; parentPortId: string }

export type PlaybookOperation = AddOperation | DeleteOperation | ReplaceOperation | RelinkOperation | MoveOperation;

export interface PlaybookSnapshotNode extends PlaybookStepSpec {
  id: string;
}

export interface PlaybookSnapshot {
  nodes: PlaybookSnapshotNode[];
  links: PlaybookDefinitionEdge[];
}

export interface PlaybookHistoryEntry {
  do: PlaybookOperation;
  undo: PlaybookOperation;
}

export interface PlaybookHistory {
  past: PlaybookHistoryEntry[];
  future: PlaybookHistoryEntry[];
}

// What an executed operation answered: the id of a created step or link.
export interface PlaybookOperationResult {
  nodeId?: string;
  linkId?: string;
}

export const PLAYBOOK_HISTORY_LIMIT = 50;

// The playbook as the canvas shows it: its steps and the links between them, add buttons left out.
export const canvasSnapshot = (nodes: Node[], edges: Edge[]): PlaybookSnapshot => ({
  nodes: nodes.filter((n) => n.type !== 'placeholder').map((n) => ({
    id: n.id,
    component_id: n.data?.component?.id ?? '',
    name: n.data?.name ?? '',
    configuration: n.data?.configuration ? JSON.stringify(n.data.configuration) : null,
    ...(n.data?.description ? { description: n.data.description } : {}),
    position: n.position,
  })),
  links: toDefinitionLinks(nodes, edges),
});

export const emptyHistory = (): PlaybookHistory => ({ past: [], future: [] });

const specOf = (node: PlaybookSnapshotNode): PlaybookStepSpec => ({
  component_id: node.component_id,
  name: node.name,
  configuration: node.configuration,
  ...(node.description ? { description: node.description } : {}),
  position: node.position,
});

const incoming = (snapshot: PlaybookSnapshot, nodeId: string) => snapshot.links.filter((l) => l.to.id === nodeId);

// The id of the single link reaching a step, the one a move replaces; undefined with 0 or several.
export const singleIncomingLinkId = (snapshot: PlaybookSnapshot, nodeId: string): string | undefined => {
  const links = incoming(snapshot, nodeId);
  return links.length === 1 ? links[0].id : undefined;
};

// The operation that cancels `op` applied on `before`, or null when none exists.
// outPortsOf answers the out port ids of a component.
export const inverseOf = (
  op: PlaybookOperation,
  before: PlaybookSnapshot,
  outPortsOf: (componentId: string) => string[],
): PlaybookOperation | null => {
  switch (op.kind) {
    case 'add':
      // A new step has no child: deleting it removes nothing else.
      return { kind: 'delete', nodeId: op.nodeId };
    case 'delete': {
      const node = before.nodes.find((n) => n.id === op.nodeId);
      if (!node) return null;
      if (before.links.some((l) => l.from.id === op.nodeId)) return null; // its branch goes with it
      const parents = incoming(before, op.nodeId);
      if (parents.length > 1) return null; // one add restores one parent only
      const [parent] = parents;
      return {
        kind: 'add',
        nodeId: op.nodeId,
        node: specOf(node),
        ...(parent ? { parentNodeId: parent.from.id, parentPortId: parent.from.port } : {}),
      };
    }
    case 'replace': {
      const node = before.nodes.find((n) => n.id === op.nodeId);
      if (!node) return null;
      // The server drops the branches of the outputs the new component does not have.
      const kept = new Set(outPortsOf(op.node.component_id));
      if (before.links.some((l) => l.from.id === op.nodeId && !kept.has(l.from.port))) return null;
      return { kind: 'replace', nodeId: op.nodeId, node: specOf(node) };
    }
    case 'relink': {
      const link = before.links.find((l) => l.id === op.linkId);
      if (!link) return null;
      return { kind: 'relink', linkId: op.linkId, toNodeId: link.to.id, fromNodeId: link.from.id, fromPortId: link.from.port };
    }
    case 'move': {
      const parents = incoming(before, op.nodeId);
      if (parents.length !== 1) return null; // a move replaces every incoming link by one
      return { kind: 'move', nodeId: op.nodeId, parentNodeId: parents[0].from.id, parentPortId: parents[0].from.port };
    }
    default:
      return null;
  }
};

export const canUndo = (history: PlaybookHistory) => history.past.length > 0;
export const canRedo = (history: PlaybookHistory) => history.future.length > 0;

const ID_FIELDS = ['nodeId', 'parentNodeId', 'toNodeId', 'fromNodeId', 'linkId'] as const;

const remapOperation = (op: PlaybookOperation, ids: Map<string, string>): PlaybookOperation => {
  const next: Record<string, unknown> = { ...op };
  ID_FIELDS.forEach((field) => {
    const value = next[field];
    if (typeof value === 'string' && ids.has(value)) next[field] = ids.get(value);
  });
  return next as unknown as PlaybookOperation;
};

const remapEntry = (entry: PlaybookHistoryEntry, ids: Map<string, string>): PlaybookHistoryEntry => ({
  do: remapOperation(entry.do, ids),
  undo: remapOperation(entry.undo, ids),
});

// A step re-created by an undo or a redo gets a new id from the server, and a move replaces the
// link reaching the step by a new one: the entries left in the history name the new ids from then
// on. `before` is the playbook the operation was executed on.
const idsAfter = (executed: PlaybookOperation, result: PlaybookOperationResult, before: PlaybookSnapshot) => {
  const ids = new Map<string, string>();
  if (executed.kind === 'add' && result.nodeId && result.nodeId !== executed.nodeId) {
    ids.set(executed.nodeId, result.nodeId);
  }
  if (executed.kind === 'move' && result.linkId) {
    const replaced = singleIncomingLinkId(before, executed.nodeId);
    if (replaced && replaced !== result.linkId) ids.set(replaced, result.linkId);
  }
  return ids;
};

// Record a change made on the canvas (`op` executed on `before`, the server answered `result`).
// A change without inverse ends the history.
export const recordOperation = (
  history: PlaybookHistory,
  op: PlaybookOperation,
  before: PlaybookSnapshot,
  outPortsOf: (componentId: string) => string[],
  result: PlaybookOperationResult = {},
): PlaybookHistory => {
  const undo = inverseOf(op, before, outPortsOf);
  if (!undo) return emptyHistory();
  const ids = idsAfter(op, result, before);
  const entry = remapEntry({ do: op, undo }, ids);
  return { past: [...history.past.map((e) => remapEntry(e, ids)), entry].slice(-PLAYBOOK_HISTORY_LIMIT), future: [] };
};

// The history once the newest entry was undone: its undo operation executed on `before`, the
// server answered `result`.
export const afterUndo = (history: PlaybookHistory, result: PlaybookOperationResult, before: PlaybookSnapshot): PlaybookHistory => {
  const entry = history.past[history.past.length - 1];
  if (!entry) return history;
  const ids = idsAfter(entry.undo, result, before);
  return {
    past: history.past.slice(0, -1).map((e) => remapEntry(e, ids)),
    future: [remapEntry(entry, ids), ...history.future.map((e) => remapEntry(e, ids))],
  };
};

// The history once the next entry was redone: its operation executed on `before`.
export const afterRedo = (history: PlaybookHistory, result: PlaybookOperationResult, before: PlaybookSnapshot): PlaybookHistory => {
  const [entry, ...rest] = history.future;
  if (!entry) return history;
  const ids = idsAfter(entry.do, result, before);
  return {
    past: [...history.past.map((e) => remapEntry(e, ids)), remapEntry(entry, ids)],
    future: rest.map((e) => remapEntry(e, ids)),
  };
};
