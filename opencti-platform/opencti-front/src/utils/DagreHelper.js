import * as dagre from 'dagre';
import * as _ from 'lodash';

function mapElements(model) {
  // dagre compatible format
  return model.nodes.map((node) => ({
    id: node.id,
    metadata: {
      width: node.type === 'entity' ? 60 : 70,
      height: node.type === 'entity' ? 60 : 25,
      id: node.id,
    },
  }));
}

function mapEdges(model) {
  // returns links which connects nodes
  // we check are there both from and to nodes in the model. Sometimes links can be detached
  return model.links
    .map((link) => ({
      from: link.source,
      to: link.target,
    }))
    .filter(
      (item) => model.nodes.find((node) => node.id === item.from)
        && model.nodes.find((node) => node.id === item.to),
    );
}

function distributeGraph(model, rankdir) {
  const nodes = mapElements(model);
  const edges = mapEdges(model);
  const graph = new dagre.graphlib.Graph();
  graph.setGraph({ ranker: 'network-simplex', rankdir });
  graph.setDefaultEdgeLabel(() => ({}));
  // add elements to dagre graph
  nodes.forEach((node) => {
    graph.setNode(node.id, node.metadata);
  });
  edges.forEach((edge) => {
    if (edge.from && edge.to) {
      graph.setEdge(edge.from, edge.to);
    }
  });
  // auto-distribute
  dagre.layout(graph);
  return graph.nodes().map((node) => graph.node(node));
}

export default function distributeElements(model, rankdir = 'LR') {
  const clonedModel = _.cloneDeep(model);
  const nodes = distributeGraph(clonedModel, rankdir);
  nodes.forEach((node) => {
    const modelNode = clonedModel.nodes.find((item) => item.id === node.id);
    modelNode.x = node.x - node.width / 2;
    modelNode.y = node.y - node.height / 2;
  });
  return clonedModel;
}
