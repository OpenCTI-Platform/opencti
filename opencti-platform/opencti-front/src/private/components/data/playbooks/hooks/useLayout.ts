import { useEffect, useRef } from 'react';
import { useReactFlow, useStore, ReactFlowState } from 'reactflow';
import { timer } from 'd3-timer';
import { layoutNodes } from './layoutNodes';
import { commitMutation } from '../../../../../relay/environment';
import { useManipulateComponentsPlaybookUpdatePositionsMutation } from './useManipulateComponents';

const options = { duration: 300 };

const nodeCountSelector = (state: ReactFlowState) => state.nodeInternals.size;

const useLayout = (playbookId: string) => {
  const initial = useRef(true);
  const nodeCount = useStore(nodeCountSelector);
  const { getNodes, getNode, setNodes, setEdges, getEdges, fitView } = useReactFlow();
  useEffect(() => {
    const nodes = getNodes();
    const edges = getEdges();
    const targetNodes = layoutNodes(nodes, edges);
    const transitions = targetNodes.map((node) => {
      return {
        id: node.id,
        // this is where the node currently is placed
        from: getNode(node.id)?.position || node.position,
        // this is where we want the node to be placed
        to: node.position,
        node,
      };
    });
    const t = timer((elapsed: number) => {
      const s = elapsed / options.duration;
      const currNodes = transitions.map(({ node, from, to }) => {
        return {
          id: node.id,
          position: {
            // simple linear interpolation
            x: from.x + (to.x - from.x) * s,
            y: from.y + (to.y - from.y) * s,
          },
          data: { ...node.data },
          type: node.type,
        };
      });
      setNodes(currNodes);
      if (elapsed > options.duration) {
        const finalNodes = transitions.map(({ node, to }) => {
          return {
            id: node.id,
            position: {
              x: to.x,
              y: to.y,
            },
            data: { ...node.data },
            type: node.type,
          };
        });
        setNodes(finalNodes);
        commitMutation({
          mutation: useManipulateComponentsPlaybookUpdatePositionsMutation,
          variables: {
            id: playbookId,
            positions: JSON.stringify(
              finalNodes.map((n) => ({
                id: n.id,
                position: n.position,
              })),
            ),
          },
          updater: undefined,
          optimisticUpdater: undefined,
          optimisticResponse: undefined,
          onCompleted: undefined,
          onError: undefined,
          setSubmitting: undefined,
        });
        t.stop();
        if (!initial.current) {
          fitView({ duration: 200, padding: 0.2 });
        }
        initial.current = false;
      }
    });
    return () => {
      t.stop();
    };
  }, [nodeCount, getEdges, getNodes, getNode, setNodes, fitView, setEdges]);
};

export default useLayout;
