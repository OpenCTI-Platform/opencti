import React from 'react';
import * as SRD from 'storm-react-diagrams';
import EntityLinkModel from './EntityLinkModel';

export default class EntityLinkFactory extends SRD.AbstractLinkFactory {
  constructor() {
    super('entity');
  }

  generateReactWidget(diagramEngine, link) {
    return React.createElement(SRD.DefaultLinkWidget, {
      link,
      diagramEngine,
    });
  }

  getNewInstance() {
    return new EntityLinkModel();
  }

  generateLinkSegment(model, widget, selected, path) {
    return (
      <path
        className={
          model.inferred
            ? widget.bem('--path-inferred')
            : selected
              ? widget.bem('--path-selected')
              : ''
        }
        strokeWidth={model.width}
        stroke={model.color}
        d={path}
      />
    );
  }
}
