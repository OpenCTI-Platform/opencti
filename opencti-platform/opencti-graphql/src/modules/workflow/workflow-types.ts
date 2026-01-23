import { ENTITY_TYPE_STATUS, ENTITY_TYPE_STATUS_TEMPLATE } from '../../schema/internalObject';
import type { BasicStoreIdentifier, BasicWorkflowStatus, BasicWorkflowTemplateEntity } from '../../types/store';

export const isEntityStatus
  = (entity: BasicStoreIdentifier): entity is BasicWorkflowStatus => entity.entity_type === ENTITY_TYPE_STATUS;

export const isEntityStatusTemplate
  = (entity: BasicStoreIdentifier): entity is BasicWorkflowTemplateEntity => entity.entity_type === ENTITY_TYPE_STATUS_TEMPLATE;
