import { useCallback, useEffect, useRef } from 'react';
import { Connection, Edge, useReactFlow } from 'reactflow';
import { graphql } from 'react-relay';
import { commitMutation, MESSAGING$ } from '../../../../../relay/environment';
import { useFormatter } from '../../../../../components/i18n';
import { applyRewire, isDrawnConnection, planConnect, PlaybookRewire, toDefinitionLinks, withoutDrawnConnections } from '../utils/playbookRewiring';
import { addPlaceholders } from '../utils/playbook';
import type { PlaybookEdge, PlaybookNode, SetPlaybookAction, SetSelectedPlaybookEdge, SetSelectedPlaybookNode } from '../types/playbook-types';
import type { PlaybookHistoryControls } from './usePlaybookHistory';

type PlaybookHistoryRecorder = Pick<PlaybookHistoryControls, 'record' | 'snapshot'>;

// The canvas no longer starts a relink (link ends are not draggable); the undo history keeps the
// operation and replays it with this mutation.
export const usePlaybookRewiringRelinkMutation = graphql`
  mutation usePlaybookRewiringRelinkMutation($id: ID!, $linkId: ID!, $toNodeId: ID!, $fromNodeId: ID, $fromPortId: ID) {
    playbookRelink(id: $id, linkId: $linkId, toNodeId: $toNodeId, fromNodeId: $fromNodeId, fromPortId: $fromPortId)
  }
`;

export const usePlaybookRewiringMoveNodeMutation = graphql`
  mutation usePlaybookRewiringMoveNodeMutation($id: ID!, $nodeId: ID!, $parentNodeId: ID!, $parentPortId: ID!) {
    playbookMoveNode(id: $id, nodeId: $nodeId, parentNodeId: $parentNodeId, parentPortId: $parentPortId)
  }
`;

// Draw a connection between an out port and a step, from either end: one write (playbookMoveNode),
// nothing deleted. A drop the plan refuses (a cycle, the entry point as a target) does nothing and
// says why.
// The handlers stay the same functions whatever the mode: React Flow 11 keeps the last handler it was
// given when the prop turns undefined, so view mode is enforced here (canEdit read at call time).
const usePlaybookRewiring = (
  playbookId: string,
  setAction: SetPlaybookAction,
  setSelectedEdge: SetSelectedPlaybookEdge,
  setSelectedNode: SetSelectedPlaybookNode,
  history?: PlaybookHistoryRecorder,
  canEdit = true,
) => {
  const { t_i18n } = useFormatter();
  const { getNodes, getEdges, setNodes, setEdges } = useReactFlow();
  const canEditRef = useRef(canEdit);
  useEffect(() => {
    canEditRef.current = canEdit;
  }, [canEdit]);

  const apply = useCallback((rewire: PlaybookRewire, newLinkId: string) => {
    const nodes = getNodes() as PlaybookNode[];
    const steps = nodes.filter((n) => n.type !== 'placeholder');
    const links = applyRewire(toDefinitionLinks(nodes, getEdges()), rewire, newLinkId);
    const stepEdges: PlaybookEdge[] = links.map((l) => ({
      id: l.id,
      type: 'workflow',
      source: l.from.id,
      sourceHandle: l.from.port,
      target: l.to.id,
      data: {
        openConfig: (edge: PlaybookEdge) => {
          setSelectedEdge(edge);
          setAction('config');
        },
      },
    }));
    const next = addPlaceholders(steps, stepEdges, setAction, setSelectedNode);
    setNodes(next.nodes as PlaybookNode[]);
    setEdges(next.edges as Edge[]);
  }, [getNodes, getEdges, setNodes, setEdges, setAction, setSelectedEdge, setSelectedNode]);

  const commit = useCallback((rewire: PlaybookRewire | null) => {
    if (!rewire) {
      MESSAGING$.notifyError(t_i18n('This link cannot go there: it would create a loop or leave a step without a parent'));
      return;
    }
    const before = history?.snapshot();
    commitMutation({
      mutation: usePlaybookRewiringMoveNodeMutation,
      variables: { id: playbookId, nodeId: rewire.nodeId, parentNodeId: rewire.parentNodeId, parentPortId: rewire.parentPortId },
      onCompleted: (response: { playbookMoveNode: string }) => {
        if (history && before) {
          history.record(
            { kind: 'move', nodeId: rewire.nodeId, parentNodeId: rewire.parentNodeId, parentPortId: rewire.parentPortId },
            before,
            { linkId: response.playbookMoveNode },
          );
        }
        apply(rewire, response.playbookMoveNode);
      },
    });
  }, [playbookId, apply, t_i18n, history]);

  const onConnect = useCallback((connection: Connection) => {
    // React Flow already drew the connection as an edge of its own: it goes away at once, so the
    // snapshot the history records is the playbook before the move (one parent for the moved step,
    // hence an undo) and a refused connection leaves nothing on the canvas.
    const edges = getEdges();
    if (edges.some(isDrawnConnection)) setEdges(withoutDrawnConnections(edges));
    // View mode: nothing is saved, whether it is the landing mode or reached with the switch.
    if (!canEditRef.current) return;
    commit(planConnect(getNodes(), getEdges(), connection));
  }, [commit, getNodes, getEdges, setEdges]);

  return { onConnect };
};

export default usePlaybookRewiring;
