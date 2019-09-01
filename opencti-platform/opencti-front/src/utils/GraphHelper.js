import { forEach, values } from 'ramda';

// eslint-disable-next-line import/prefer-default-export
export const serializeGraph = (model) => {
  const nodes = model.getNodes();
  const graphData = {};
  graphData.nodes = {};
  forEach((n) => {
    graphData.nodes[n.extras.id] = {
      position: n.getPosition(),
    };
  }, values(nodes));
  graphData.zoom = model.getZoomLevel();
  graphData.offsetX = model.getOffsetX();
  graphData.offsetY = model.getOffsetY();
  return Buffer.from(JSON.stringify(graphData)).toString('base64');
};
