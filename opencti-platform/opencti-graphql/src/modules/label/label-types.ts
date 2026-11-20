import type { BasicStoreEntity } from '../../types/store';

// BasicStoreEntity types its color as a string: a label may have none, which the import and the export handle
export interface BasicStoreEntityLabel extends Omit<BasicStoreEntity, 'color'> {
  value: string;
  color?: string | null;
}
