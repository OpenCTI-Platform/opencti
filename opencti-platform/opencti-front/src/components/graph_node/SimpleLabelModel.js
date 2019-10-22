import { LabelModel } from 'storm-react-diagrams';
import { mergeRight } from 'ramda';

export default class SimpleLabelModel extends LabelModel {
  constructor() {
    super('simple');
    this.offsetY = -23;
    this.selected = false;
    this.extras = null;
  }

  setLabel(label) {
    this.label = label;
  }

  setExtras(extras) {
    this.extras = extras;
  }

  deSerialize(ob, engine) {
    super.deSerialize(ob, engine);
    this.extras = ob.extras;
  }

  serialize() {
    return mergeRight(super.serialize(), {
      label: this.label,
      extras: this.extras,
    });
  }

  isSelected() {
    return this.selected;
  }

  setSelected(selected) {
    this.selected = selected;
    this.props.model.parent.iterateListeners((listener, event) => {
      if (listener.selectionChanged) {
        listener.selectionChanged({
          ...event,
          openEdit: true,
          inferred: this.props.model.parent.inferred,
          isSelected: selected,
        });
      }
    });
  }
}
