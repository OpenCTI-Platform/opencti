import type { StixDate, StixOpenctiExtensionSDO } from '../../types/stix-2-1-common';
import { STIX_EXT_OCTI, STIX_EXT_OCTI_TIMELINE } from '../../types/stix-2-1-extensions';
import type { StixContainer } from '../../types/stix-2-1-sdo';
import type { StixContainer as Stix2Container } from '../../types/stix-2-0-sdo';
import type { BasicStoreEntity, StoreEntity } from '../../types/store';

export const ENTITY_TYPE_CONTAINER_TASK = 'Task';

export interface BasicStoreEntityTask extends BasicStoreEntity {
  name: string;
  description: string;
  due_date: string;
  completes_containment?: boolean;
}

export interface StoreEntityTask extends StoreEntity {
  name: string;
  description: string;
  due_date: string;
  completes_containment?: boolean;
}

export interface StixTaskTimelineExtension {
  extension_type: 'property-extension';
  completes_containment: boolean;
}

export interface StixTask extends StixContainer {
  name: string;
  description: string;
  due_date: StixDate;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO;
    [STIX_EXT_OCTI_TIMELINE]?: StixTaskTimelineExtension;
  };
}

// STIX 2.0
export interface Stix2Task extends Stix2Container {
  name: string;
  description: string;
  due_date: StixDate;
}
