import { AbstractPortFactory } from 'storm-react-diagrams';
import EntityPortModel from './EntityPortModel';

export default class EntityPortFactory extends AbstractPortFactory {
  constructor() {
    super('entity');
  }

  static getNewInstance(initialConfig) {
    return new EntityPortModel(initialConfig);
  }
}
