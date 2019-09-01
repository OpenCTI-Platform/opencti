import React from 'react';
import * as SRD from 'storm-react-diagrams';
import EntityLinkModel from './EntityLinkModel';

export default class EntityLinkFactory extends SRD.AbstractLinkFactory {
  constructor() {
    super('entity');
  }

  // eslint-disable-next-line class-methods-use-this
  generateReactWidget(diagramEngine, link) {
    return React.createElement(SRD.DefaultLinkWidget, {
      link,
      diagramEngine,
    });
  }

  // eslint-disable-next-line class-methods-use-this
  getNewInstance() {
    return new EntityLinkModel();
  }

  // eslint-disable-next-line class-methods-use-this
  generateLinkSegment(model, widget, selected, path) {
    const classNameNotInferred = selected ? widget.bem('--path-selected') : '';
    return (
      <path
        className={
          model.inferred ? widget.bem('--path-inferred') : classNameNotInferred
        }
        strokeWidth={model.width}
        stroke={model.color}
        d={path}
      />
    );
  }
}
