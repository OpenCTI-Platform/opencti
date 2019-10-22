import { LinkModel } from 'storm-react-diagrams';
import { mergeRight } from 'ramda';
import GlobalLabelModel from './GlobalLabelModel';

export default class GlobalLinkModel extends LinkModel {
  constructor(type = 'global') {
    super(type);
    this.color = '#00bcd4';
    this.width = 3;
    this.curvyness = 50;
  }

  serialize() {
    return mergeRight(super.serialize(), {
      width: this.width,
      color: this.color,
      curvyness: this.curvyness,
    });
  }

  deSerialize(ob, engine) {
    super.deSerialize(ob, engine);
    this.color = ob.color;
    this.width = ob.width;
    this.curvyness = ob.curvyness;
  }

  getPosition() {
    return { x: this.x, y: this.y };
  }

  addLabel(label) {
    if (label instanceof GlobalLabelModel) {
      return super.addLabel(label);
    }
    const labelOb = new GlobalLabelModel();
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

  setExtras(data) {
    this.data = data;
  }

  setLabel(label) {
    this.labels = [];
    if (label instanceof GlobalLabelModel) {
      return super.addLabel(label);
    }
    const labelOb = new GlobalLabelModel();
    labelOb.setLabel(label);
    return super.addLabel(labelOb);
  }
}
