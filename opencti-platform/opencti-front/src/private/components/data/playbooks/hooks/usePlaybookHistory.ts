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

import { Dispatch, SetStateAction, useCallback, useMemo, useRef, useState } from 'react';
import { Edge, useReactFlow } from 'reactflow';
import { graphql } from 'react-relay';
import { commitMutation, fetchQuery } from '../../../../../relay/environment';
import { useManipulateComponentsAddNodeMutation, useManipulateComponentsDeleteNodeMutation, useManipulateComponentsReplaceNodeMutation } from './useManipulateComponents';
import { usePlaybookRewiringMoveNodeMutation, usePlaybookRewiringRelinkMutation } from './usePlaybookRewiring';
import {
  afterRedo,
  afterUndo,
  canRedo,
  canUndo,
  canvasSnapshot,
  emptyHistory,
  type PlaybookHistory,
  type PlaybookOperation,
  type PlaybookOperationResult,
  type PlaybookSnapshot,
  recordOperation,
} from '../utils/playbookHistory';
import { addPlaceholders, computeEdges, computeNodes } from '../utils/playbook';
import { outPorts } from '../types/nodes/playbookNodeGeometry';
import type { PlaybookComponents, PlaybookDefinitionEdge, PlaybookDefinitionNode, PlaybookNode } from '../types/playbook-types';

export const usePlaybookHistoryDefinitionQuery = graphql`
  query usePlaybookHistoryDefinitionQuery($id: String!) {
    playbook(id: $id) {
      id
      playbook_definition
    }
  }
`;

type SetString = Dispatch<SetStateAction<string | null>>;

interface DefinitionResponse {
  playbook?: { playbook_definition?: string | null } | null;
}

export interface PlaybookHistoryControls {
  // A change made on the canvas: `op` was executed on `before`, the server answered `result`.
  record: (op: PlaybookOperation, before: PlaybookSnapshot, result?: PlaybookOperationResult) => void;
  // A change without inverse (a step inserted on a link): the history ends.
  reset: () => void;
  snapshot: () => PlaybookSnapshot;
  undo: () => void;
  redo: () => void;
  canUndo: boolean;
  canRedo: boolean;
}

// Undo / redo of the editor session (Ctrl/Cmd+Z, Shift+Ctrl/Cmd+Z): each step runs the existing
// mutation of its inverse operation, then the canvas is rebuilt from the playbook the server holds,
// so what is shown is always what is saved. A failed step ends the history.
const usePlaybookHistory = (
  playbookId: string,
  playbookComponents: PlaybookComponents,
  setAction: SetString,
  setSelectedNode: SetString,
  setSelectedEdge: SetString,
): PlaybookHistoryControls => {
  const { getNodes, getEdges, setNodes, setEdges } = useReactFlow();
  const [history, setHistory] = useState<PlaybookHistory>(emptyHistory);
  const historyRef = useRef(history);
  const busy = useRef(false);

  const update = useCallback((next: PlaybookHistory) => {
    historyRef.current = next;
    setHistory(next);
  }, []);

  const outPortsOf = useCallback((componentId: string) => {
    const component = playbookComponents.find((c) => c?.id === componentId);
    return outPorts(component?.ports).map((p) => p.id);
  }, [playbookComponents]);

  const snapshot = useCallback(() => canvasSnapshot(getNodes(), getEdges()), [getNodes, getEdges]);

  const record = useCallback((op: PlaybookOperation, before: PlaybookSnapshot, result: PlaybookOperationResult = {}) => {
    update(recordOperation(historyRef.current, op, before, outPortsOf, result));
  }, [outPortsOf, update]);

  const reset = useCallback(() => update(emptyHistory()), [update]);

  const reload = useCallback(async () => {
    const response = await fetchQuery(usePlaybookHistoryDefinitionQuery, { id: playbookId }, { fetchPolicy: 'network-only' })
      .toPromise() as DefinitionResponse | undefined;
    const definition = JSON.parse(response?.playbook?.playbook_definition || '{}') as {
      nodes?: PlaybookDefinitionNode[];
      links?: PlaybookDefinitionEdge[];
    };
    const nodes = computeNodes(definition.nodes ?? [], playbookComponents, setAction, setSelectedNode);
    const edges = computeEdges(definition.links ?? [], setAction, setSelectedEdge);
    const next = addPlaceholders(nodes, edges, setAction, setSelectedNode);
    setNodes(next.nodes as PlaybookNode[]);
    setEdges(next.edges as Edge[]);
  }, [playbookId, playbookComponents, setAction, setSelectedNode, setSelectedEdge, setNodes, setEdges]);

  const execute = useCallback((op: PlaybookOperation): Promise<PlaybookOperationResult> => new Promise((resolve, reject) => {
    const onError = (error: Error) => reject(error);
    switch (op.kind) {
      case 'add':
        commitMutation({
          mutation: useManipulateComponentsAddNodeMutation,
          variables: {
            id: playbookId,
            input: {
              ...op.node,
              ...(op.parentNodeId && op.parentPortId ? { parentNodeId: op.parentNodeId, parentPortId: op.parentPortId } : {}),
            },
          },
          onCompleted: (response: { playbookAddNode: string }) => resolve({ nodeId: response.playbookAddNode }),
          onError,
        });
        return;
      case 'delete':
        commitMutation({
          mutation: useManipulateComponentsDeleteNodeMutation,
          variables: { id: playbookId, nodeId: op.nodeId },
          onCompleted: () => resolve({}),
          onError,
        });
        return;
      case 'replace':
        commitMutation({
          mutation: useManipulateComponentsReplaceNodeMutation,
          variables: { id: playbookId, nodeId: op.nodeId, input: op.node },
          onCompleted: () => resolve({}),
          onError,
        });
        return;
      case 'relink':
        commitMutation({
          mutation: usePlaybookRewiringRelinkMutation,
          variables: { id: playbookId, linkId: op.linkId, toNodeId: op.toNodeId, fromNodeId: op.fromNodeId, fromPortId: op.fromPortId },
          onCompleted: () => resolve({ linkId: op.linkId }),
          onError,
        });
        return;
      default:
        commitMutation({
          mutation: usePlaybookRewiringMoveNodeMutation,
          variables: { id: playbookId, nodeId: op.nodeId, parentNodeId: op.parentNodeId, parentPortId: op.parentPortId },
          onCompleted: (response: { playbookMoveNode: string }) => resolve({ linkId: response.playbookMoveNode }),
          onError,
        });
    }
  }), [playbookId]);

  const step = useCallback(async (direction: 'undo' | 'redo') => {
    const current = historyRef.current;
    const entry = direction === 'undo' ? current.past[current.past.length - 1] : current.future[0];
    if (!entry || busy.current) return;
    busy.current = true;
    setSelectedNode(null);
    setSelectedEdge(null);
    setAction(null);
    const before = snapshot();
    try {
      const result = await execute(direction === 'undo' ? entry.undo : entry.do);
      update(direction === 'undo' ? afterUndo(current, result, before) : afterRedo(current, result, before));
    } catch {
      // The server refused the step (the playbook changed elsewhere): nothing older can be trusted.
      update(emptyHistory());
    } finally {
      try {
        await reload();
      } finally {
        busy.current = false;
      }
    }
  }, [execute, reload, snapshot, update, setAction, setSelectedNode, setSelectedEdge]);

  const undo = useCallback(() => {
    step('undo');
  }, [step]);
  const redo = useCallback(() => {
    step('redo');
  }, [step]);

  return useMemo(() => ({
    record,
    reset,
    snapshot,
    undo,
    redo,
    canUndo: canUndo(history),
    canRedo: canRedo(history),
  }), [record, reset, snapshot, undo, redo, history]);
};

export default usePlaybookHistory;
