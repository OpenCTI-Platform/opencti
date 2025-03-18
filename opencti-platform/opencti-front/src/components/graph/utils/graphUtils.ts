import { ObjectToParse } from './useGraphParser';
import { GraphState } from '../graph.types';

/**
 * Determines if a point is inside a polygon.
 * A point is in a polygon if a line from the point to infinity crosses the polygon an odd number of times.
 *
 * @param polygon Polygon to check on.
 * @param point Point to see if inside polygon.
 * @returns True if the point is inside the polygon.
 */
// eslint-disable-next-line import/prefer-default-export
export const pointInPolygon = (
  polygon: number[][],
  point: [number, number],
) => {
  let odd = false;
  // For each edge (In this case for each point of the polygon and the previous one)
  for (let i = 0, j = polygon.length - 1; i < polygon.length; i += 1) {
    // If a line from the point into infinity crosses this edge
    if (
      polygon[i][1] > point[1] !== polygon[j][1] > point[1] // One point needs to be above, one below our y coordinate
      // ...and the edge doesn't cross our Y coordinate before our x coordinate (but between our x coordinate and infinity)
      && point[0]
      < ((polygon[j][0] - polygon[i][0]) * (point[1] - polygon[i][1]))
      / (polygon[j][1] - polygon[i][1])
      + polygon[i][0]
    ) {
      odd = !odd;
    }
    j = i;
  }
  // If the number of crossings was odd, the point is in the polygon
  return odd;
};

interface ContainerEdges {
  edges: readonly ({
    types?: readonly (string | undefined | null)[] | undefined | null
    node: object
  } | null | undefined)[] | undefined | null
}
interface GraphQueryData {
  objects: {
    edges: readonly ({
      types?: readonly (string | undefined | null)[] | undefined | null
      node: object & {
        reports?: ContainerEdges | undefined | null
        groupings?: ContainerEdges | undefined | null
        cases?: ContainerEdges | undefined | null
      }
    } | null | undefined)[] | undefined | null
  } | undefined | null
}

/**
 * Helper function to prepare data received from query to be able to
 * understand by graph component.
 *
 * @param data Query data.
 * @returns Comprehensive data for Graph.
 */
export const getObjectsToParse = (data: GraphQueryData) => {
  return (data.objects?.edges ?? []).flatMap((n) => {
    if (!n) return []; // filter empty nodes.
    // For correlation.
    const linkedContainers = [
      ...(n.node.reports?.edges ?? []),
      ...(n.node.groupings?.edges ?? []),
      ...(n.node.cases?.edges ?? []),
    ].flatMap((e) => (e ? e.node : []));
    return { ...n.node, types: n.types, linkedContainers };
  }) as unknown as ObjectToParse[];
};

/**
 * Helper function to keep only a subset of graph state properties
 * that need to be saved in local storage and URL params.
 *
 * @param state The state of the graph.
 * @returns Subset of graph state that need to be saved.
 */
export const graphStateToLocalStorage = (state: GraphState) => {
  const {
    disabledCreators,
    disabledEntityTypes,
    disabledMarkings,
    mode3D,
    modeTree,
    withForces,
  } = state;

  return {
    disabledCreators,
    disabledEntityTypes,
    disabledMarkings,
    mode3D,
    modeTree,
    withForces,
  };
};
