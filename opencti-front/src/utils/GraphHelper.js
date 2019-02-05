import { forEach, values } from 'ramda';

export const serializeGraph = (model) => {
  const nodes = model.getNodes();
  const graphData = {};
  graphData.nodes = {};
  forEach((n) => {
    graphData.nodes[n.extras.id] = {
      position: n.getPosition(),
      expanded: n.getExpanded(),
    };
  }, values(nodes));
  graphData.zoom = model.getZoomLevel();
  graphData.offsetX = model.getOffsetX();
  graphData.offsetY = model.getOffsetY();
  return Buffer.from(JSON.stringify(graphData)).toString('base64');
};