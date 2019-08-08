import React from 'react';
import * as SRD from 'storm-react-diagrams';
import EntityNodeWidget from './EntityNodeWidget';
import EntityNodeModel from './EntityNodeModel';

export default class EntityNodeFactory extends SRD.AbstractNodeFactory {
  constructor() {
    super('entity');
  }

  static generateReactWidget(diagramEngine, node) {
    return <EntityNodeWidget node={node} />;
  }

  static getNewInstance(initialConfig) {
    return new EntityNodeModel(initialConfig);
  }
}
