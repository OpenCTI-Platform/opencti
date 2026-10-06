import { convertIdentityToStix } from '../../database/stix-2-1-converter';
import { convertIdentityToStix as convertIdentityToStix_2_0 } from '../../database/stix-2-0-converter';
import { ENTITY_TYPE_IDENTITY_CITIZENSHIP_DOCUMENT } from './citizenshipDocument-types';
import type { Stix2CitizenshipDocument, StixCitizenshipDocument, StoreEntityCitizenshipDocument } from './citizenshipDocument-types';
import type { StoreEntity } from '../../types/store';
import { assertType } from '../../database/stix-converter-utils';

const convertCitizenshipDocumentToStix = (instance: StoreEntityCitizenshipDocument): StixCitizenshipDocument => {
  return convertIdentityToStix(instance, instance.entity_type);
};

export const convertCitizenshipDocumentToStix_2_0 = (instance: StoreEntity): Stix2CitizenshipDocument => {
  assertType(ENTITY_TYPE_IDENTITY_CITIZENSHIP_DOCUMENT, instance.entity_type);
  const citizenshipDocument = instance as StoreEntityCitizenshipDocument;
  return {
    ...convertIdentityToStix_2_0(instance, instance.entity_type),
    citizenship_document_type: citizenshipDocument.citizenship_document_type,
  };
};

export default convertCitizenshipDocumentToStix;
