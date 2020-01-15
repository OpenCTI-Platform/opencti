import { NodeModel } from 'storm-react-diagrams';
import GlobalPortModel from './GlobalPortModel';

export default class EntityNodeModel extends NodeModel {
  constructor(data) {
    super('entity');
    this.addPort(new GlobalPortModel('main'));
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
