import type { StixDomainObject, StixOpenctiExtension } from '../../types/stix-common';
import { STIX_EXT_MITRE, STIX_EXT_OCTI } from '../../types/stix-extensions';
import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { DataComponent } from '../../generated/graphql';

export const INPUT_DATA_COMPONENT = 'dataComponent';
export interface BasicStoreEntityDataSource extends BasicStoreEntity {
  name: string;
  description: string;
  collection_layers: Array<string>;
}

export interface StoreEntityDataSource extends StoreEntity {
  name: string;
  description: string;
  collection_layers: Array<string>;
  [INPUT_DATA_COMPONENT]: DataComponent
}

export interface StixDataSource extends StixDomainObject {
  name: string;
  description: string;
  platforms: string[];
  collection_layers: string[];
  aliases: Array<string>;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtension
    [STIX_EXT_MITRE]: {
      'extension_type': 'new-sdo'
    }
  };
}
