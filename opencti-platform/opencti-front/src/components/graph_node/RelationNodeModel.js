import { NodeModel } from 'storm-react-diagrams';
import RelationPortModel from './GlobalPortModel';

export default class RelationNodeModel extends NodeModel {
  constructor(data) {
    super('relation');
    this.addPort(new RelationPortModel('main'));
    this.extras = data;
  }

  getPosition() {
    return { x: this.x, y: this.y };
  }

  setExtras(data) {
    this.extras = data;
  }

  setExpandable(expandable) {
    this.expandable = expandable;
  }

  getExpandable() {
    return this.expandable;
  }
}
