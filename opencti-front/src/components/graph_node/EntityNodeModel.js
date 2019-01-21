import { NodeModel } from 'storm-react-diagrams';
import EntityPortModel from './EntityPortModel';

export default class EntityNodeModel extends NodeModel {
  constructor(data) {
    super('entity');
    this.addPort(new EntityPortModel('top'));
    this.addPort(new EntityPortModel('left'));
    this.addPort(new EntityPortModel('bottom'));
    this.addPort(new EntityPortModel('right'));
    this.extras = data;
  }
}