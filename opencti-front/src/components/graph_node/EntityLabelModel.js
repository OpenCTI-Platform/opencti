import { LabelModel } from 'storm-react-diagrams';
import { mergeRight } from 'ramda';

export default class EntityLabelModel extends LabelModel {
  constructor() {
    super('entity');
    this.offsetY = -23;
  }

  setLabel(label) {
    this.label = label;
  }

  deSerialize(ob, engine) {
    super.deSerialize(ob, engine);
    this.label = ob.label;
  }

  serialize() {
    return mergeRight(super.serialize(), {
      label: this.label,
    });
  }
}
