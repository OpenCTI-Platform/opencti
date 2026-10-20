import { useLayoutEffect, useState } from 'react';
import { useGraphContext } from '../GraphContext';
import { isNotEmptyField } from '../../../utils/utils';

/**
 * Sets the `disabled` flag of every node and link from the filters of the graph state. The graph
 * objects are shared with the renderer, so the flags are set once the filters are committed, in a
 * layout effect, never while rendering; the returned token then changes, and what is derived from
 * the flags (collapsed groups, highlighted path, empty state) is computed again before the frame
 * is painted.
 */
const useGraphFilter = (): object => {
  const [token, setToken] = useState<object>({});
  const { graphData, graphState } = useGraphContext();
  const {
    disabledEntityTypes,
    disabledCreators,
    disabledMarkings,
    selectedTimeRangeInterval,
    disabledRelationshipTypes = [],
  } = graphState;

  const filterNodes = (disabledTargets: string[]) => {
    graphData?.nodes.forEach((node) => {
      node.disabled = disabledEntityTypes.includes(node.entity_type)
        // A nested relationship, drawn as a node, fades with its relationship type.
        || (!!node.relationship_type && disabledRelationshipTypes.includes(node.relationship_type))
        || disabledCreators.includes(node.createdBy.id)
        || disabledTargets.includes(node.id)
        || node.markedBy.some((marking) => disabledMarkings.includes(marking.id));
    });
  };

  const filterLinks = () => {
    const targets: string[] = [];
    graphData?.links.forEach((link) => {
      link.disabled = disabledCreators.includes(link.createdBy.id)
        || link.markedBy.some((marking) => disabledMarkings.includes(marking.id))
        || (isNotEmptyField(link.defaultDate)
          && !!selectedTimeRangeInterval
          && ((isNotEmptyField(link.start_time) && link.start_time < selectedTimeRangeInterval[0])
            || (isNotEmptyField(link.stop_time) && link.stop_time > selectedTimeRangeInterval[1])
            || link.defaultDate < selectedTimeRangeInterval[0]
            || link.defaultDate > selectedTimeRangeInterval[1]));
      if (link.disabled) {
        targets.push(link.target_id);
      }
      // A relationship type turned off in the legend fades its links, not the entities they join.
      if (disabledRelationshipTypes.includes(link.relationship_type || link.entity_type)) {
        link.disabled = true;
      }
    });
    return targets;
  };

  useLayoutEffect(() => {
    const disabledTargets = filterLinks();
    filterNodes(disabledTargets);
    setToken({});
  }, [
    disabledEntityTypes,
    disabledCreators,
    disabledMarkings,
    selectedTimeRangeInterval,
    disabledRelationshipTypes,
    graphData,
  ]);
  return token;
};

export default useGraphFilter;
