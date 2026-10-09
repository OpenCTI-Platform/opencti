import type { BasicStoreEntity, StoreEntity } from '../../../types/store';

export const ENTITY_TYPE_CASE_TEMPLATE = 'Case-Template';
export const TEMPLATE_TASK_RELATION = 'template-task';

export interface BasicStoreEntityCaseTemplate extends BasicStoreEntity {
  name: string;
  description: string;
  tasks: string[];
}

export interface StoreEntityCaseTemplate extends StoreEntity {
  name: string;
  description: string;
  tasks: string[];
}
