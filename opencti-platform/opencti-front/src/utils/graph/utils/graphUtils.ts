/**
 * Determines if a point is inside a polygon.
 * A point is in a polygon if a line from the point to infinity crosses the polygon an odd number of times.
 *
 * @param polygon Polygon to check on.
 * @param point Point to see if inside polygon.
 * @returns True if the point is inside the polygon.
 */
export const pointInPolygon = (
  polygon: [number, number][],
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
