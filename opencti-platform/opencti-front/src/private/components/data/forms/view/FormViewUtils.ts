import * as Yup from 'yup';
import { FormSchemaDefinition, FormFieldDefinition } from '../Form.d';

const getYupValidationForField = (
  field: FormFieldDefinition,
  t_i18n: (key: string) => string,
): Yup.Schema<unknown> => {
  let validation: Yup.Schema<unknown>;

  switch (field.type) {
    case 'text':
    case 'textarea':
    case 'select':
    case 'date':
    case 'datetime':
      validation = Yup.string();
      break;
    case 'number':
      validation = Yup.number()
        .typeError(t_i18n('Must be a number'));
      break;
    case 'checkbox':
    case 'toggle':
      validation = Yup.boolean();
      break;
    case 'multiselect':
    case 'objectMarking':
    case 'objectLabel':
    case 'files':
      validation = Yup.array();
      break;
    case 'createdBy':
      validation = Yup.object().nullable();
      break;
    default:
      validation = Yup.string();
  }

  // Add required validation if field is mandatory
  if (field.isMandatory) {
    if (field.type === 'multiselect' || field.type === 'objectMarking'
        || field.type === 'objectLabel' || field.type === 'files') {
      validation = (validation as any).min(1, t_i18n('This field is required'));
    } else if (field.type === 'checkbox' || field.type === 'toggle') {
      // For boolean fields, we might want to ensure they're checked
      // But usually mandatory booleans means they must be explicitly set, not necessarily true
      // So we'll skip required validation for booleans
    } else {
      validation = validation.required(t_i18n('This field is required'));
    }
  }

  return validation;
};

export const convertFormSchemaToYupSchema = (
  schema: FormSchemaDefinition,
  t_i18n: (key: string) => string,
): Yup.ObjectSchema<Record<string, unknown>> => {
  const shape: Record<string, Yup.Schema<unknown>> = {};

  // Process main entity fields
  const mainEntityFields = schema.fields.filter((field) => field.attributeMapping.entity === 'main_entity');

  mainEntityFields.forEach((field) => {
    shape[field.name] = getYupValidationForField(field, t_i18n);
  });

  // Process additional entities
  if (schema.additionalEntities) {
    schema.additionalEntities.forEach((entity) => {
      const entityShape: Record<string, Yup.Schema<unknown>> = {};
      // Find fields for this additional entity
      const entityFields = schema.fields.filter((field) => field.attributeMapping.entity === entity.id);
      entityFields.forEach((field) => {
        entityShape[field.name] = getYupValidationForField(field, t_i18n);
      });
      shape[`additional_${entity.id}`] = Yup.object().shape(entityShape);
    });
  }

  return Yup.object().shape(shape);
};

export const formatFormDataForSubmission = (
  values: Record<string, unknown>,
  schema: FormSchemaDefinition,
): Record<string, any> => {
  const formattedData: Record<string, any> = {};

  // Process main entity fields
  const mainEntityFields = schema.fields.filter((field) => field.attributeMapping.entity === 'main_entity');
  mainEntityFields.forEach((field) => {
    const value = values[field.name];
    if (value !== undefined && value !== null && value !== '') {
      // Use the field's name as the key for submission
      formattedData[field.name] = value;
    }
  });

  // Process additional entities
  if (schema.additionalEntities && schema.additionalEntities.length > 0) {
    schema.additionalEntities.forEach((entity) => {
      const entityValues = values[`additional_${entity.id}`] || {};
      // Find fields for this additional entity
      const entityFields = schema.fields.filter((field) => field.attributeMapping.entity === entity.id);
      entityFields.forEach((field) => {
        const value = (entityValues as any)[field.name];
        if (value !== undefined && value !== null && value !== '') {
          // Use the field's name as the key for submission
          formattedData[field.name] = value;
        }
      });
    });
  }

  return formattedData;
};
