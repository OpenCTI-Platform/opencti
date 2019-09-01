import { AbstractPortFactory } from 'storm-react-diagrams';
import EntityPortModel from './EntityPortModel';

export default class EntityPortFactory extends AbstractPortFactory {
  constructor() {
    super('entity');
  }

  // eslint-disable-next-line class-methods-use-this
  getNewInstance() {
    return new EntityPortModel();
  }
}
