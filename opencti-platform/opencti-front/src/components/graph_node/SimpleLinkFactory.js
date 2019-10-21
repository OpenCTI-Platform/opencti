import React from 'react';
import * as SRD from 'storm-react-diagrams';
import SimpleLinkModel from './SimpleLinkModel';

export default class SimpleLinkFactory extends SRD.AbstractLinkFactory {
  constructor() {
    super('simple');
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
    return new SimpleLinkModel();
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
