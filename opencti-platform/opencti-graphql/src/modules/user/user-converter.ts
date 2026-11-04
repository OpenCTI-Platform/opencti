import { buildStixObject } from '../../database/stix-2-1-converter';
import type { StixUser, StoreEntityUser } from './user-types';

const convertUserToStix = (instance: StoreEntityUser): StixUser => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    name: instance.name,
  };
};

export default convertUserToStix;
