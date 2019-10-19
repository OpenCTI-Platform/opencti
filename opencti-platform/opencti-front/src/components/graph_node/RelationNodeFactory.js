import React from 'react';
import * as SRD from 'storm-react-diagrams';
import RelationNodeWidget from './RelationNodeWidget';
import RelationNodeModel from './RelationNodeModel';

export default class RelationNodeFactory extends SRD.AbstractNodeFactory {
  constructor() {
    super('relation');
  }

  // eslint-disable-next-line class-methods-use-this
  generateReactWidget(diagramEngine, node) {
    return <RelationNodeWidget node={node} />;
  }

  // eslint-disable-next-line class-methods-use-this
  getNewInstance() {
    return new RelationNodeModel();
  }
}