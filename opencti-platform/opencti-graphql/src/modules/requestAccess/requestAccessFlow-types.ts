import type { StixObject } from '../../types/stix-common';
import type { BasicStoreEntity, StoreEntity } from '../../types/store';

export const ENTITY_TYPE_REQUEST_ACCESS_FLOW = 'RequestAccessFlow';

export interface BasicStoreEntityRequestAccessFlow extends BasicStoreEntity {
  from: string
  to: string
  rfi_workflow_id: string
}

export interface StoreEntityRequestAccessFlow extends StoreEntity {
  from: string
  to: string
  rfi_workflow_id: string
}

export interface StixRequestAccessFlow extends StixObject {
  from: string
  to: string
  rfi_workflow_id: string
}
