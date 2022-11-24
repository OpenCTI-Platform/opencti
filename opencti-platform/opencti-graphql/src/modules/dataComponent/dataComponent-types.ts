import type { StixDomainObject, StixMitreExtension, StixOpenctiExtension } from '../../types/stix-common';
import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import { STIX_EXT_MITRE, STIX_EXT_OCTI } from '../../types/stix-extensions';
import type { DataSource } from '../../generated/graphql';

export const INPUT_DATA_SOURCE = 'dataSource';

export interface BasicStoreEntityDataComponent extends BasicStoreEntity {
  name: string;
  description: string;
}

export interface StoreEntityDataComponent extends StoreEntity {
  name: string;
  description: string;
  [INPUT_DATA_SOURCE]: DataSource
}

export interface StixDataComponent extends StixDomainObject {
  name: string;
  description: string;
  aliases: Array<string>;
  dataSource: DataSource;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtension
    [STIX_EXT_MITRE]: StixMitreExtension;
  };
}
