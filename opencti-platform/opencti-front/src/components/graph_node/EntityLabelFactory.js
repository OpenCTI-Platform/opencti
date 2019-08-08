import React from 'react';
import * as SRD from 'storm-react-diagrams';
import EntityLabelWidget from './EntityLabelWidget';
import EntityLabelModel from './EntityLabelModel';

export default class EntityLabelFactory extends SRD.AbstractLabelFactory {
  constructor() {
    super('entity');
  }

  static generateReactWidget(diagramEngine, label) {
    return <EntityLabelWidget model={label} />;
  }

  static getNewInstance(initialConfig) {
    return new EntityLabelModel(initialConfig);
  }
}
