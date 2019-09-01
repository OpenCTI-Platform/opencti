import React from 'react';
import * as SRD from 'storm-react-diagrams';
import EntityLabelWidget from './EntityLabelWidget';
import EntityLabelModel from './EntityLabelModel';

export default class EntityLabelFactory extends SRD.AbstractLabelFactory {
  constructor() {
    super('entity');
  }

  // eslint-disable-next-line class-methods-use-this
  generateReactWidget(diagramEngine, label) {
    return <EntityLabelWidget model={label} />;
  }

  // eslint-disable-next-line class-methods-use-this
  getNewInstance() {
    return new EntityLabelModel();
  }
}
