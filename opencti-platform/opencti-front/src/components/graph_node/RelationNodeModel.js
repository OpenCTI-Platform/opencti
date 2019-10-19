import { NodeModel } from 'storm-react-diagrams';
import RelationPortModel from './GlobalPortModel';

export default class RelationNodeModel extends NodeModel {
  constructor(data) {
    super('relation');
    this.addPort(new RelationPortModel('main'));
    this.extras = data;
  }

  setSelected(selected) {
    this.selected = selected;
    this.iterateListeners((listener, event) => {
      if (listener.selectionChanged) {
        listener.selectionChanged({ ...event, isSelected: selected });
      }
    });
  }

  getPosition() {
    return { x: this.x, y: this.y };
  }

  setExpandable(expandable) {
    this.expandable = expandable;
  }

  getExpandable() {
    return this.expandable;
  }
}
