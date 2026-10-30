import type { BasicStoreEntity } from '../../types/store';

export interface BasicStoreEntityLabel extends BasicStoreEntity {
  value: string;
  color: string;
}
