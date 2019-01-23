import { PortModel, DefaultLinkModel } from 'storm-react-diagrams';
import { mergeRight } from 'ramda';

export default class EntityPortModel extends PortModel {
  constructor(pos = 'top') {
    super(pos, 'entity');
    this.position = pos;
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

  createLinkModel() {
    return new DefaultLinkModel();
  }
}