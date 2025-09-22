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
      validation = (validation as Yup.ArraySchema<unknown[], Yup.AnyObject>).min(1, t_i18n('This field is required'));
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
): Record<string, unknown> => {
  const formattedData: Record<string, unknown> = {};

  // Helper function to extract proper values for special field types
  const extractFieldValue = (field: FormFieldDefinition, value: unknown): unknown => {
    if (value === undefined || value === null || value === '') {
      return undefined;
    }

    // Handle special reference fields
    if (field.type === 'createdBy') {
      // Extract the internal ID from the object
      if (typeof value === 'object' && value !== null) {
        const obj = value as Record<string, unknown>;
        return obj.value || obj.id;
      }
      return value;
    }

    if (field.type === 'objectMarking') {
      // Extract internal IDs from the array of marking objects
      if (Array.isArray(value)) {
        return value.map((m: Record<string, unknown>) => m?.value || m?.id || m).filter((id: unknown) => id);
      }
      return value;
    }

    if (field.type === 'objectLabel') {
      // Extract label values from the array of label objects
      if (Array.isArray(value)) {
        return value.map((l: Record<string, unknown>) => l?.label || l?.value || l).filter((label: unknown) => label);
      }
      return value;
    }

    return value;
  };

  // Process main entity fields
  const mainEntityFields = schema.fields.filter((field) => field.attributeMapping.entity === 'main_entity');
  mainEntityFields.forEach((field) => {
    const extractedValue = extractFieldValue(field, values[field.name]);
    if (extractedValue !== undefined) {
      formattedData[field.name] = extractedValue;
    }
  });

  // Process additional entities
  if (schema.additionalEntities && schema.additionalEntities.length > 0) {
    schema.additionalEntities.forEach((entity) => {
      const entityValues = values[`additional_${entity.id}`] || {};
      // Find fields for this additional entity
      const entityFields = schema.fields.filter((field) => field.attributeMapping.entity === entity.id);
      entityFields.forEach((field) => {
        const value = (entityValues as Record<string, unknown>)[field.name];
        const extractedValue = extractFieldValue(field, value);
        if (extractedValue !== undefined) {
          formattedData[field.name] = extractedValue;
        }
      });
    });
  }

  return formattedData;
};
