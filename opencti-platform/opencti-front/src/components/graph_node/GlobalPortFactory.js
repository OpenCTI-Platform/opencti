import { AbstractPortFactory } from 'storm-react-diagrams';
import GlobalPortModel from './GlobalPortModel';

export default class GlobalPortFactory extends AbstractPortFactory {
  constructor() {
    super('global');
  }

  // eslint-disable-next-line class-methods-use-this
  getNewInstance() {
    return new GlobalPortModel();
  }
}
