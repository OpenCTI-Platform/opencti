import React from 'react';
import * as SRD from 'storm-react-diagrams';
import EntityNodeWidget from './EntityNodeWidget';
import EntityNodeModel from './EntityNodeModel';

export default class EntityNodeFactory extends SRD.AbstractNodeFactory {
  constructor() {
    super('entity');
  }

  generateReactWidget(diagramEngine, node) {
    return <EntityNodeWidget node={node} />;
  }

  getNewInstance() {
    return new EntityNodeModel();
  }
}