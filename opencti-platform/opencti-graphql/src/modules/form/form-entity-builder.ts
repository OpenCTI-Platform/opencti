import { v4 as uuidv4 } from 'uuid';
import type { StoreEntity } from '../../types/store';
import type { StixId } from '../../types/stix-2-1-common';
import { generateStandardId } from '../../schema/identifier';
import { isEmptyField } from '../../database/utils';
import { isStixDomainObject } from '../../schema/stixDomainObject';
import { convertIdentityClass } from './form-utils';

export const completeEntity = (entityType: string, entity: StoreEntity) => {
  const finalEntity = entity;
  finalEntity.standard_id = generateStandardId(entityType, entity) as StixId;
  finalEntity.internal_id = uuidv4();
  if (isStixDomainObject(entityType)) {
    if (isEmptyField(finalEntity.created)) {
      finalEntity.created = new Date();
    }
    if (isEmptyField(finalEntity.modified)) {
      finalEntity.modified = new Date();
    }
    convertIdentityClass(entityType, entity);
  }
  finalEntity.id = finalEntity.internal_id;
  return finalEntity;
};
