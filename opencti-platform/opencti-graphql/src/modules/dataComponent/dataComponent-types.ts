import type { StixDomainObject, StixId, StixOpenctiExtension } from '../../types/stix-common';
import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import { STIX_EXT_MITRE, STIX_EXT_OCTI } from '../../types/stix-extensions';
import type { BasicStoreEntityDataSource } from '../dataSource/dataSource-types';

export const RELATION_DATA_SOURCE = 'data-source';
export const ATTRIBUTE_DATA_SOURCE = 'data_source_ref';
export const INPUT_DATA_SOURCE = 'dataSource';

export interface BasicStoreEntityDataComponent extends BasicStoreEntity {
  name: string;
  description: string;
}

export interface StoreEntityDataComponent extends StoreEntity {
  name: string;
  description: string;
  [INPUT_DATA_SOURCE]: BasicStoreEntityDataSource
}

export interface StixDataComponent extends StixDomainObject {
  name: string;
  description: string;
  aliases: Array<string>;
  data_source_ref: StixId | undefined;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtension
    [STIX_EXT_MITRE]: {
      'extension_type': 'new-sdo'
    }
  };
}
