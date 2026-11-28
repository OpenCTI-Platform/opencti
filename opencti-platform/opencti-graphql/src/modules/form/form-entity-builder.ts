import { v4 as uuidv4 } from 'uuid';
import type { StoreEntity } from '../../types/store';
import type { StixId } from '../../types/stix-2-1-common';
import { generateStandardId } from '../../schema/identifier';
import { isEmptyField } from '../../database/utils';
import { isStixDomainObject } from '../../schema/stixDomainObject';
import { convertIdentityClass } from './form-utils';

export const completeEntity = (entityType: string, entity: StoreEntity) => {
  const finalEntity = entity;
  finalEntity.internal_id = uuidv4();
  if (isStixDomainObject(entityType)) {
    if (isEmptyField(finalEntity.created)) {
      finalEntity.created = new Date();
    }
    if (isEmptyField(finalEntity.modified)) {
      finalEntity.modified = new Date();
    }
    // A date mapped from a field is a raw string: the platform stores it as a date, and the id uses its canonical form
    (['created', 'modified'] as const).forEach((key) => {
      const date = typeof finalEntity[key] === 'string' ? new Date(finalEntity[key]) : undefined;
      if (date && !Number.isNaN(date.getTime())) {
        (finalEntity as any)[key] = date;
      }
    });
    convertIdentityClass(entityType, entity);
  }
  // After the defaults: the id of some types depends on created (Task, cases, Note...), the platform recomputes it from the stored value
  finalEntity.standard_id = generateStandardId(entityType, entity) as StixId;
  finalEntity.id = finalEntity.internal_id;
  return finalEntity;
};
