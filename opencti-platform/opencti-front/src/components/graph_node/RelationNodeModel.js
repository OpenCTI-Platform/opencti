import { NodeModel } from 'storm-react-diagrams';
import RelationPortModel from './GlobalPortModel';

export default class RelationNodeModel extends NodeModel {
  constructor(data) {
    super('relation');
    this.addPort(new RelationPortModel('main'));
    this.extras = data;
  }

  setSelectedCustom(selected, edit = false, remove = false) {
    this.selected = selected;
    this.iterateListeners((listener, event) => {
      if (listener.selectionChanged) {
        listener.selectionChanged({
          ...event,
          edit,
          remove,
          isSelected: selected,
        });
      }
    });
  }

  setExtras(data) {
    this.extras = data;
  }
  
  getPosition() {
    return { x: this.x, y: this.y };
  }
}
