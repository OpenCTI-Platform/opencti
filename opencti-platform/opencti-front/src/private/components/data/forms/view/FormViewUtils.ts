import * as Yup from 'yup';
import { FormSchemaDefinition, FormFieldDefinition } from '../Form';

export const convertFormSchemaToYupSchema = (
  schema: FormSchemaDefinition,
  t_i18n: (key: string) => string,
): Yup.ObjectSchema<any> => {
  const shape: Record<string, any> = {};

  // Process main entity fields
  const mainEntityFields = schema.fields.filter((field) => field.attributeMapping.entity === 'main_entity');
  mainEntityFields.forEach((field) => {
    shape[field.name] = getYupValidationForField(field, t_i18n);
  });

  // Process additional entities
  if (schema.additionalEntities) {
    schema.additionalEntities.forEach((entity) => {
      const entityShape: Record<string, any> = {};
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

const getYupValidationForField = (
  field: FormFieldDefinition,
  t_i18n: (key: string) => string,
): any => {
  let validation: any;

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
      validation = validation.min(1, t_i18n('This field is required'));
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

export const formatFormDataForSubmission = (
  values: any,
  schema: FormSchemaDefinition,
): any => {
  const formattedData: any = {
    mainEntity: {
      type: schema.mainEntityType,
      fields: {},
    },
  };

  // Process main entity fields
  const mainEntityFields = schema.fields.filter((field) => field.attributeMapping.entity === 'main_entity');
  mainEntityFields.forEach((field) => {
    if (values[field.name] !== undefined && values[field.name] !== null && values[field.name] !== '') {
      formattedData.mainEntity.fields[field.name] = values[field.name];
    }
  });

  // Process additional entities
  if (schema.additionalEntities && schema.additionalEntities.length > 0) {
    formattedData.additionalEntities = [];
    schema.additionalEntities.forEach((entity) => {
      const entityData: any = {
        type: entity.entityType,
        label: entity.label,
        fields: {},
      };

      const entityValues = values[`additional_${entity.id}`] || {};
      // Find fields for this additional entity
      const entityFields = schema.fields.filter((field) => field.attributeMapping.entity === entity.id);
      entityFields.forEach((field) => {
        if (entityValues[field.name] !== undefined
            && entityValues[field.name] !== null
            && entityValues[field.name] !== '') {
          entityData.fields[field.name] = entityValues[field.name];
        }
      });

      formattedData.additionalEntities.push(entityData);
    });
  }

  // Process relationships if any
  if (schema.relationships && schema.relationships.length > 0) {
    formattedData.relationships = schema.relationships.map((rel) => ({
      fromEntity: rel.fromEntity,
      toEntity: rel.toEntity,
      relationshipType: rel.relationshipType,
    }));
  }

  return formattedData;
};
