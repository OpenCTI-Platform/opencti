import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixDomainObject, StixOpenctiExtensionSDO } from '../../types/stix-common';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';

export const RELATION_SUBNARRATIVE_OF = 'subnarrative-of';
export const ENTITY_TYPE_NARRATIVE = 'Narrative';

// region Database types
export interface BasicStoreEntityNarrative extends BasicStoreEntity {
  name: string;
  description: string;
  narrative_types: Array<string>;
}

export interface StoreEntityNarrative extends StoreEntity {
  name: string;
  description: string;
  narrative_types: Array<string>;
}
// endregion

// region Stix type
export interface StixNarrative extends StixDomainObject {
  name: string;
  description: string;
  narrative_types: Array<string>;
  aliases: Array<string>;
  extensions: {
    [STIX_EXT_OCTI] : StixOpenctiExtensionSDO
  };
}
// endregion
