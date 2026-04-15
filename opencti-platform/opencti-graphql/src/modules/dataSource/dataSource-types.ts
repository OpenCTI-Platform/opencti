import type { StixDomainObject, StixOpenctiExtension } from '../../types/stix-2-1-common';
import type { StixDomainObject as StixDomainObject2 } from '../../types/stix-2-0-common';
import { STIX_EXT_MITRE, STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
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
  [INPUT_DATA_COMPONENT]: DataComponent;
}

export interface StixDataSource extends StixDomainObject {
  name: string;
  description: string;
  platforms: string[];
  collection_layers: string[];
  aliases: Array<string>;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtension;
    [STIX_EXT_MITRE]: {
      extension_type: 'new-sdo';
    };
  };
}

// region Stix 2.0 type
export interface Stix2DataSource extends StixDomainObject2 {
  name: string;
  description: string;
  aliases: Array<string>;
  x_mitre_platforms: Array<string>;
  x_mitre_collection_layers: Array<string>;
}
// endregion
