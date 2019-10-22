import React from 'react';
import * as SRD from 'storm-react-diagrams';
import GlobalLinkModel from './GlobalLinkModel';
import GlobalLinkWidget from './GlobalLinkWidget';

export default class GlobalLinkFactory extends SRD.AbstractLinkFactory {
  constructor() {
    super('global');
  }

  // eslint-disable-next-line class-methods-use-this
  generateReactWidget(diagramEngine, link) {
    return React.createElement(GlobalLinkWidget, {
      link,
      diagramEngine,
    });
  }

  // eslint-disable-next-line class-methods-use-this
  getNewInstance() {
    return new GlobalLinkModel();
  }

  // eslint-disable-next-line class-methods-use-this
  generateLinkSegment(model, widget, selected, path) {
    return <path strokeWidth={model.width} stroke={model.color} d={path} />;
  }
}
