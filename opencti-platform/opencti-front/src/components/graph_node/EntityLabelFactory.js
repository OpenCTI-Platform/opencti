import React from 'react';
import * as SRD from 'storm-react-diagrams';
import EntityLabelWidget from './EntityLabelWidget';
import EntityLabelModel from './EntityLabelModel';

export default class EntityLabelFactory extends SRD.AbstractLabelFactory {
  constructor() {
    super('entity');
  }

  generateReactWidget(diagramEngine, label) {
    return <EntityLabelWidget model={label} />;
  }

  getNewInstance() {
    return new EntityLabelModel();
  }
}
