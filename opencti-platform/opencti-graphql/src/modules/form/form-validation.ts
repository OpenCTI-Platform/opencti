import type { FormSchemaDefinition } from './form-types';
import { isEmptyField, isNotEmptyField } from '../../database/utils';
import { FunctionalError } from '../../config/errors';

export const validateFormSubmission = (
  schema: FormSchemaDefinition,
  values: Record<string, any>,
): void => {
  const errors: string[] = [];

  // Main entity
  if (schema.mainEntityLookup && isEmptyField(values.mainEntityLookup)) {
    errors.push('Required field "mainEntityLookup" is missing');
  }
  if (!schema.mainEntityLookup && schema.mainEntityMultiple && schema.mainEntityFieldMode === 'multiple') {
    schema.fields.filter((field) => field.attributeMapping.entity === 'main_entity').forEach((field) => {
      if (field.isMandatory || field.required) {
        if (isEmptyField(values.mainEntityGroups)) {
          errors.push('Required field "mainEntityGroups" is missing');
        } else {
          for (let index = 0; index < values.mainEntityGroups.length; index += 1) {
            const fieldValue = values.mainEntityGroups[index][field.name];
            if (isEmptyField(fieldValue)) {
              errors.push(`Required field "${field.label || field.name}" is missing`);
            }
          }
        }
      }
    });
  }
  if (!schema.mainEntityLookup && schema.mainEntityMultiple && schema.mainEntityFieldMode === 'parsed') {
    if (isEmptyField(values.mainEntityParsed)) {
      errors.push('Required field "mainEntityParsed" is missing');
    }
    if (values.mainEntityFields) {
      schema.fields.filter((field) => field.attributeMapping.entity === 'main_entity').forEach((field) => {
        if (field.isMandatory || field.required) {
          const fieldValue = values.mainEntityFields[field.attributeMapping.attributeName] ?? values.mainEntityFields[field.name];
          if (isEmptyField(fieldValue)) {
            errors.push(`Required field "${field.label || field.name}" is missing`);
          }
        }
      });
    }
  }
  if (!schema.mainEntityLookup && !schema.mainEntityMultiple) {
    schema.fields.filter((field) => field.attributeMapping.entity === 'main_entity').forEach((field) => {
      if (field.isMandatory || field.required) {
        const fieldValue = values[field.name];
        if (isEmptyField(fieldValue)) {
          errors.push(`Required field "${field.label || field.name}" is missing`);
        }
      }
    });
  }

  // Additional entities
  if (schema.additionalEntities) {
    for (let index = 0; index < schema.additionalEntities.length; index += 1) {
      const additionalEntity = schema.additionalEntities[index];
      if (additionalEntity.lookup && isEmptyField(values[`additional_${additionalEntity.id}_lookup`]) && (additionalEntity?.minAmount ?? 0) > 0) {
        errors.push(`Required field "additional_${additionalEntity.id}_lookup" is missing`);
      }
      if (!additionalEntity.lookup && additionalEntity.multiple && additionalEntity.fieldMode === 'multiple') {
        schema.fields.filter((field) => field.attributeMapping.entity === additionalEntity.id).forEach((field) => {
          if (field.isMandatory || field.required) {
            if (!values[`additional_${additionalEntity.id}_groups`]) {
              errors.push(`Required field "additional_${additionalEntity.id}_groups" is missing`);
            } else {
              for (let index2 = 0; index2 < values[`additional_${additionalEntity.id}_groups`].length; index2 += 1) {
                const fieldValue = values[`additional_${additionalEntity.id}_groups`][index2][field.name];
                if (isEmptyField(fieldValue)) {
                  errors.push(`Required field "${field.label || field.name}" is missing`);
                }
              }
            }
          }
        });
      }
      if (!additionalEntity.lookup && additionalEntity.multiple && additionalEntity.fieldMode === 'parsed') {
        if ((additionalEntity?.minAmount ?? 0) > 0 && !values[`additional_${additionalEntity.id}_parsed`]) {
          errors.push(`Required field "additional_${additionalEntity.id}_parsed" is missing`);
        }
        if (values[`additional_${additionalEntity.id}_fields`]) {
          schema.fields.filter((field) => field.attributeMapping.entity === additionalEntity.id).forEach((field) => {
            if (field.isMandatory || field.required) {
              const fieldValue = values[`additional_${additionalEntity.id}_fields`][field.attributeMapping.attributeName] ?? values[`additional_${additionalEntity.id}_fields`][field.name];
              if (isEmptyField(fieldValue)) {
                errors.push(`Required field "${field.label || field.name}" is missing`);
              }
            }
          });
        }
      }
      if (!additionalEntity.lookup && !additionalEntity.multiple) {
        const entityFields = schema.fields.filter((field) => field.attributeMapping.entity === additionalEntity.id);
        const entityData = values[`additional_${additionalEntity.id}`];

        let hasAnyFieldFilled = false;
        if (entityData && typeof entityData === 'object') {
          hasAnyFieldFilled = entityFields.some((field) => {
            const fieldValue = entityData[field.name];
            return isNotEmptyField(fieldValue);
          });
        }

        if (additionalEntity.required || hasAnyFieldFilled) {
          entityFields.forEach((field) => {
            if (field.isMandatory || field.required) {
              const fieldValue = entityData ? entityData[field.name] : undefined;
              if (isEmptyField(fieldValue)) {
                errors.push(`Required field "${field.label || field.name}" is missing`);
              }
            }
          });
        }
      }
    }
  }

  if (errors.length > 0) {
    throw FunctionalError(errors.join(', '));
  }
};
