import { NodeModel } from 'storm-react-diagrams';
import EntityPortModel from './EntityPortModel';

export default class EntityNodeModel extends NodeModel {
  constructor(data) {
    super('entity');
    this.addPort(new EntityPortModel('main'));
    this.extras = data;
  }
}