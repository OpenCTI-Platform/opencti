import { LabelModel } from 'storm-react-diagrams';
import { mergeRight } from 'ramda';

export default class EntityLabelModel extends LabelModel {
  constructor() {
    super('entity');
    this.offsetY = -23;
    this.selected = false;
    this.firstSeen = null;
    this.lastSeen = null;
  }

  setLabel(label) {
    this.label = label;
  }

  setFirstSeen(firstSeen) {
    this.firstSeen = firstSeen;
  }

  setLastSeen(lastSeen) {
    this.lastSeen = lastSeen;
  }

  deSerialize(ob, engine) {
    super.deSerialize(ob, engine);
    this.label = ob.label;
    this.firstSeen = ob.firstSeen;
    this.lastSeen = ob.lastSeen;
  }

  serialize() {
    return mergeRight(super.serialize(), {
      label: this.label,
      firstSeen: this.firstSeen,
      lastSeen: this.lastSeen,
    });
  }

  isSelected() {
    return this.selected;
  }

  setSelected(selected) {
    this.selected = selected;
    this.props.model.parent.iterateListeners((listener, event) => {
      if (listener.selectionChanged) {
        listener.selectionChanged({ ...event, openEdit: true, isSelected: selected });
      }
    });
  }
}
