import { useCallback } from 'react';
import { Connection, Edge, useReactFlow } from 'reactflow';
import { graphql } from 'react-relay';
import { commitMutation, MESSAGING$ } from '../../../../../relay/environment';
import { useFormatter } from '../../../../../components/i18n';
import { applyRewire, planConnect, planEdgeUpdate, PlaybookRewire, toDefinitionLinks } from '../utils/playbookRewiring';
import { addPlaceholders } from '../utils/playbook';
import type { PlaybookEdge, PlaybookNode, SetPlaybookAction, SetSelectedPlaybookEdge, SetSelectedPlaybookNode } from '../types/playbook-types';
import type { PlaybookHistoryControls } from './usePlaybookHistory';

type PlaybookHistoryRecorder = Pick<PlaybookHistoryControls, 'record' | 'snapshot'>;

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

// Drag a link end to another step, or draw a connection from an out port to a step: one write
// (playbookRelink or playbookMoveNode), nothing deleted. A drop the plan refuses (a cycle, a step
// left without a parent, the entry point as a target) does nothing and says why.
const usePlaybookRewiring = (
  playbookId: string,
  setAction: SetPlaybookAction,
  setSelectedEdge: SetSelectedPlaybookEdge,
  setSelectedNode: SetSelectedPlaybookNode,
  history?: PlaybookHistoryRecorder,
) => {
  const { t_i18n } = useFormatter();
  const { getNodes, getEdges, setNodes, setEdges } = useReactFlow();

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
    if (rewire.kind === 'relink') {
      commitMutation({
        mutation: usePlaybookRewiringRelinkMutation,
        variables: { id: playbookId, linkId: rewire.linkId, toNodeId: rewire.toNodeId, fromNodeId: rewire.fromNodeId, fromPortId: rewire.fromPortId },
        onCompleted: () => {
          const from = before?.links.find((l) => l.id === rewire.linkId)?.from;
          const fromNodeId = rewire.fromNodeId ?? from?.id;
          const fromPortId = rewire.fromPortId ?? from?.port;
          if (history && before && fromNodeId && fromPortId) {
            history.record({ kind: 'relink', linkId: rewire.linkId, toNodeId: rewire.toNodeId, fromNodeId, fromPortId }, before);
          }
          apply(rewire, rewire.linkId);
        },
      });
      return;
    }
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
    commit(planConnect(getNodes(), getEdges(), connection));
  }, [commit, getNodes, getEdges]);

  const onEdgeUpdate = useCallback((oldEdge: Edge, connection: Connection) => {
    commit(planEdgeUpdate(getNodes(), getEdges(), oldEdge, connection));
  }, [commit, getNodes, getEdges]);

  return { onConnect, onEdgeUpdate };
};

export default usePlaybookRewiring;
