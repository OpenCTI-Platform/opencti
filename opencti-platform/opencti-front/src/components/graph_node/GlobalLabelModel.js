import { LabelModel } from 'storm-react-diagrams';

export default class GlobalLabelModel extends LabelModel {
  constructor(label = '') {
    super('global');
    this.offsetY = -23;
    this.label = label;
  }

  setLabel(label) {
    this.label = label;
  }
}