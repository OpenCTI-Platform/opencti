import { PortModel } from 'storm-react-diagrams';
import { mergeRight } from 'ramda';
import GlobalLinkModel from './GlobalLinkModel';

export default class GlobalPortModel extends PortModel {
  constructor(pos = 'top', locked = false) {
    super(pos, 'global');
    this.position = pos;
    this.locked = locked;
  }

  serialize() {
    return mergeRight(super.serialize(), {
      position: this.position,
    });
  }

  deSerialize(data, engine) {
    super.deSerialize(data, engine);
    this.position = data.position;
  }

  // eslint-disable-next-line class-methods-use-this
  createLinkModel() {
    return new GlobalLinkModel();
  }
}
