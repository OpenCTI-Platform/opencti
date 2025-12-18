import { ENTITY_TYPE_STATUS, ENTITY_TYPE_STATUS_TEMPLATE } from '../../schema/internalObject';
import type { BasicStoreCommon, BasicWorkflowStatus, BasicWorkflowTemplateEntity } from '../../types/store';

export const isEntityStatus
  = (entity: BasicStoreCommon): entity is BasicWorkflowStatus => entity.entity_type === ENTITY_TYPE_STATUS;

export const isEntityTemplate
  = (entity: BasicStoreCommon): entity is BasicWorkflowTemplateEntity => entity.entity_type === ENTITY_TYPE_STATUS_TEMPLATE;
