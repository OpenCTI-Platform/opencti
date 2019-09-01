import React from 'react';
import * as SRD from 'storm-react-diagrams';
import EntityNodeWidget from './EntityNodeWidget';
import EntityNodeModel from './EntityNodeModel';

export default class EntityNodeFactory extends SRD.AbstractNodeFactory {
  constructor() {
    super('entity');
  }

  // eslint-disable-next-line class-methods-use-this
  generateReactWidget(diagramEngine, node) {
    return <EntityNodeWidget node={node} />;
  }

  // eslint-disable-next-line class-methods-use-this
  getNewInstance() {
    return new EntityNodeModel();
  }
}
