import { buildStixObject } from '../../../database/stix-2-1-converter';
import type { StixDocument, StoreEntityDocument } from './document-types';

const convertDocumentToStix = (instance: StoreEntityDocument): StixDocument => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    name: instance.name,
  };
};

export default convertDocumentToStix;
