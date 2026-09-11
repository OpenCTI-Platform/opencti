import { DOC_INCORRECT_OBSERVABLE_FORMAT, FunctionalError } from '../../config/errors';
import { isEmptyField } from '../../database/utils';
import { isStixCyberObservable } from '../../schema/stixCyberObservable';
import { checkObservableSyntax } from '../../utils/syntax';
import type { AuthContext, AuthUser } from '../../types/user';
import type { StoreEntity } from '../../types/store';
import { ENTITY_TYPE_CONTAINER_GROUPING } from '../grouping/grouping-types';
import { ENTITY_TYPE_MALWARE } from '../../schema/stixDomainObject';
import { completeEntity } from './form-entity-builder';
import { convertFieldType, transformSpecialFields } from './form-fields-converter';
import type { FormFieldDefinition } from './form-types';

type MaterializedEntity = StoreEntity & Record<string, unknown>;

export interface MaterializeOptions {
  seedEntity?: Partial<StoreEntity>;
  applyFields: boolean;
  skipEmptyFieldValues: boolean;
  isBypass: boolean;
  applyTypeDefaults: boolean;
  errorLabel: string;
}

export const materializeEntityFromFields = async (
  context: AuthContext,
  user: AuthUser,
  entityType: string,
  fields: FormFieldDefinition[],
  resolveFieldValue: (field: FormFieldDefinition) => unknown,
  options: MaterializeOptions,
): Promise<StoreEntity> => {
  let entity = { entity_type: entityType, ...options.seedEntity } as MaterializedEntity;

  if (options.applyFields) {
    for (const field of fields) {
      const fieldValue = field.isReadOnly && !options.isBypass
        ? field.defaultValue
        : resolveFieldValue(field);
      if (options.skipEmptyFieldValues && (fieldValue === undefined || fieldValue === null || fieldValue === '')) {
        continue;
      }
      const convertedValue = convertFieldType(fieldValue, field);
      entity[field.attributeMapping.attributeName] = convertedValue;
    }
    entity = await transformSpecialFields(context, user, entity, fields, false) as MaterializedEntity;
  }

  if (options.applyTypeDefaults) {
    if (entityType === ENTITY_TYPE_MALWARE && isEmptyField(entity.is_family)) {
      entity.is_family = true;
    }
    if (entityType === ENTITY_TYPE_CONTAINER_GROUPING && isEmptyField(entity.context)) {
      entity.context = 'form';
    }
  }

  entity = completeEntity(entityType, entity) as MaterializedEntity;
  if (isStixCyberObservable(entity.entity_type) && checkObservableSyntax(entity.entity_type, entity) !== true) {
    throw FunctionalError(options.errorLabel, {
      type: entity.entity_type,
      input: entity,
      doc_code: DOC_INCORRECT_OBSERVABLE_FORMAT,
    });
  }
  return entity;
};
