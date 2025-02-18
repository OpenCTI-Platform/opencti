import { useEffect } from 'react';
import { useGraphContext } from './GraphContext';

const useGraphFilter = () => {
  const { graphData, graphState } = useGraphContext();
  const { disabledEntityTypes, disabledCreators, disabledMarkings } = graphState;

  const filterNodes = (disabledTargets: string[]) => {
    graphData?.nodes.forEach((node) => {
      // eslint-disable-next-line no-param-reassign
      node.disabled = disabledEntityTypes.includes(node.entity_type)
        || disabledCreators.includes(node.createdBy.id)
        || disabledTargets.includes(node.id)
        || node.markedBy.some((marking) => disabledMarkings.includes(marking.id));
    });
  };

  const filterLinks = () => {
    const targets: string[] = [];
    graphData?.links.forEach((link) => {
      // eslint-disable-next-line no-param-reassign
      link.disabled = disabledCreators.includes(link.createdBy.id)
        || link.markedBy.some((marking) => disabledMarkings.includes(marking.id));
      if (link.disabled) {
        targets.push(link.target_id);
      }
    });
    return targets;
  };

  useEffect(() => {
    const disabledTargets = filterLinks();
    filterNodes(disabledTargets);
  }, [disabledEntityTypes, disabledCreators, disabledMarkings]);
};

export default useGraphFilter;
