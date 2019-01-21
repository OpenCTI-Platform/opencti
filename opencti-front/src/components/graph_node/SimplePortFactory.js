import { PortModel, AbstractPortFactory } from 'storm-react-diagrams';

export default class SimplePortFactory extends AbstractPortFactory {
  constructor(type, cb = PortModel) {
    super(type);
    this.cb = cb;
  }

  getNewInstance(initialConfig) {
    return this.cb(initialConfig);
  }
}