import React from 'react';
import * as SRD from 'storm-react-diagrams';
import GlobalLinkModel from './GlobalLinkModel';

export default class GlobalLinkFactory extends SRD.AbstractLinkFactory {
  constructor() {
    super('global');
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
    return new GlobalLinkModel();
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
        onContextMenu={(event) => {
          console.log(event);
          event.preventDefault();
          event.stopPropagation();
        }}
      />
    );
  }
}
