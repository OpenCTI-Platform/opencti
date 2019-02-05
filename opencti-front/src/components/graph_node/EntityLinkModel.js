import { LinkModel } from 'storm-react-diagrams';
import { mergeRight } from 'ramda';
import EntityLabelModel from './EntityLabelModel';

export default class EntityLinkModel extends LinkModel {
  constructor(type = 'entity') {
    super(type);
    this.color = '#00bcd4';
    this.width = 3;
    this.curvyness = 50;
    this.inferred = false;
  }

  serialize() {
    return mergeRight(super.serialize(), {
      width: this.width,
      color: this.color,
      curvyness: this.curvyness,
      inferred: this.inferred,
    });
  }

  deSerialize(ob, engine) {
    super.deSerialize(ob, engine);
    this.color = ob.color;
    this.width = ob.width;
    this.curvyness = ob.curvyness;
    this.inferred = ob.inferred;
  }

  addLabel(label) {
    if (label instanceof EntityLabelModel) {
      return super.addLabel(label);
    }
    const labelOb = new EntityLabelModel();
    labelOb.setLabel(label);
    return super.addLabel(labelOb);
  }

  setWidth(width) {
    this.width = width;
    this.iterateListeners((listener, event) => {
      if (listener.widthChanged) {
        listener.widthChanged({ ...event, width });
      }
    });
  }

  setColor(color) {
    this.color = color;
    this.iterateListeners((listener, event) => {
      if (listener.colorChanged) {
        listener.colorChanged({ ...event, color });
      }
    });
  }

  setExtras(extras) {
    this.extras = extras;
  }

  setLabels(labels) {
    this.labels = labels;
  }

  setInferred(inferred) {
    this.inferred = inferred;
  }
}
