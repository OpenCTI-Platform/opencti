import React from 'react';
import * as SRD from 'storm-react-diagrams';
import GlobalLabelWidget from './GlobalLabelWidget';
import GlobalLabelModel from './GlobalLabelModel';

export default class GlobalLabelFactory extends SRD.AbstractLabelFactory {
  constructor() {
    super('global');
  }

  // eslint-disable-next-line class-methods-use-this
  generateReactWidget(diagramEngine, label) {
    return <GlobalLabelWidget model={label} />;
  }

  // eslint-disable-next-line class-methods-use-this
  getNewInstance() {
    return new GlobalLabelModel();
  }
}
