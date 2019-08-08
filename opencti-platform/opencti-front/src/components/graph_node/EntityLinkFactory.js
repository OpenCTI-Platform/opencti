import React from 'react';
import * as SRD from 'storm-react-diagrams';
import EntityLinkModel from './EntityLinkModel';

export default class EntityLinkFactory extends SRD.AbstractLinkFactory {
  constructor() {
    super('entity');
  }

  static generateReactWidget(diagramEngine, link) {
    return React.createElement(SRD.DefaultLinkWidget, {
      link,
      diagramEngine,
    });
  }

  static getNewInstance(initialConfig) {
    return new EntityLinkModel(initialConfig);
  }
}
