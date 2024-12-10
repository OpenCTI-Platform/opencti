import type { StixRequestAccess, StoreEntityRequestAccess } from './requestAccess-types';
import { buildStixObject } from '../../database/stix-converter';

const convertRequestAccessToStix = (instance: StoreEntityRequestAccess): StixRequestAccess => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    name: instance.name,
  };
};

export default convertRequestAccessToStix;
