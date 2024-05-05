import type { StoreEntity } from './store';

export interface StoreConnector extends StoreEntity {
  active: boolean
}
