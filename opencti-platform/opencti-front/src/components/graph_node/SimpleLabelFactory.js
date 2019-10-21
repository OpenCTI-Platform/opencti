import React from 'react';
import * as SRD from 'storm-react-diagrams';
import SimpleLabelWidget from './SimpleLabelWidget';
import SimpleLabelModel from './SimpleLabelModel';

export default class SimpleLabelFactory extends SRD.AbstractLabelFactory {
  constructor() {
    super('simple');
  }

  // eslint-disable-next-line class-methods-use-this
  generateReactWidget(diagramEngine, label) {
    return <SimpleLabelWidget model={label} />;
  }

  // eslint-disable-next-line class-methods-use-this
  getNewInstance() {
    return new SimpleLabelModel();
  }
}
