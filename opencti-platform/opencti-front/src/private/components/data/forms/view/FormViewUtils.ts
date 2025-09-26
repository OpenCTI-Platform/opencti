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
  if (schema.mainEntityLookup) {
    // For lookup mode, validate the lookup field
    if (schema.mainEntityMultiple) {
      shape.mainEntityLookup = Yup.array().min(1, t_i18n('Please select at least one entity'));
    } else {
      shape.mainEntityLookup = Yup.object().nonNullable(t_i18n('Please select an entity'));
    }
  } else if (schema.mainEntityMultiple && schema.mainEntityFieldMode === 'parsed') {
    // For parsed mode, validate the text field
    shape.mainEntityParsed = Yup.string().required(t_i18n('This field is required'));

    // Also add validation for additional fields in parsed mode
    const mainEntityFields = schema.fields.filter((field) => field.attributeMapping.entity === 'main_entity');
    const fieldsShape: Record<string, Yup.Schema<unknown>> = {};
    mainEntityFields.forEach((field: FormFieldDefinition) => {
      fieldsShape[field.name] = getYupValidationForField(field, t_i18n);
    });
    if (Object.keys(fieldsShape).length > 0) {
      shape.mainEntityFields = Yup.object().shape(fieldsShape);
    }
  } else if (schema.mainEntityMultiple && schema.mainEntityFieldMode === 'multiple') {
    // For multi mode, validate the field groups
    const fieldShape: Record<string, Yup.Schema<unknown>> = {};
    const mainEntityFields = schema.fields.filter((field) => field.attributeMapping.entity === 'main_entity');
    mainEntityFields.forEach((field: FormFieldDefinition) => {
      fieldShape[field.name] = getYupValidationForField(field, t_i18n);
    });
    shape.mainEntityGroups = Yup.array()
      .of(Yup.object().shape(fieldShape))
      .min(1, t_i18n('At least one entity is required'));
  } else {
    const mainEntityFields = schema.fields.filter((field) => field.attributeMapping.entity === 'main_entity');
    mainEntityFields.forEach((field: FormFieldDefinition) => {
      shape[field.name] = getYupValidationForField(field, t_i18n);
    });
  }

  // Process additional entities
  if (schema.additionalEntities) {
    schema.additionalEntities.forEach((entity) => {
      const entityFields = schema.fields.filter((field) => field.attributeMapping.entity === entity.id);

      if (entity.lookup) {
        // Lookup mode
        if (entity.multiple) {
          const minAmount = entity.minAmount || 0;
          let validation = Yup.array();
          if (minAmount > 0) {
            validation = validation.min(minAmount, t_i18n(`Please select at least ${minAmount} entity(ies)`));
          }
          shape[`additional_${entity.id}_lookup`] = validation;
        } else {
          let validation = Yup.object().nullable();
          if (entity.required) {
            validation = Yup.object().nonNullable(t_i18n('Please select an entity'));
          }
          shape[`additional_${entity.id}_lookup`] = validation;
        }
      } else if (entity.multiple && entity.fieldMode === 'parsed') {
        // Parsed mode
        const minAmount = entity.minAmount || 0;
        let validation = Yup.string();
        if (minAmount > 0) {
          validation = validation.required(t_i18n('This field is required'));
        }
        shape[`additional_${entity.id}_parsed`] = validation;

        // Also add validation for additional fields in parsed mode
        const fieldsShape: Record<string, Yup.Schema<unknown>> = {};
        entityFields.forEach((field: FormFieldDefinition) => {
          fieldsShape[field.name] = getYupValidationForField(field, t_i18n);
        });
        if (Object.keys(fieldsShape).length > 0) {
          shape[`additional_${entity.id}_fields`] = Yup.object().shape(fieldsShape);
        }
      } else if (entity.multiple && entity.fieldMode === 'multiple') {
        // Multi mode
        const fieldShape: Record<string, Yup.Schema<unknown>> = {};
        entityFields.forEach((field: FormFieldDefinition) => {
          fieldShape[field.name] = getYupValidationForField(field, t_i18n);
        });
        const minAmount = entity.minAmount || 0;
        let validation = Yup.array().of(Yup.object().shape(fieldShape));
        if (minAmount > 0) {
          validation = validation.min(minAmount, t_i18n(`At least ${minAmount} entity(ies) required`));
        }
        shape[`additional_${entity.id}_groups`] = validation;
      } else {
        // Single entity mode
        const entityShape: Record<string, Yup.Schema<unknown>> = {};
        entityFields.forEach((field: FormFieldDefinition) => {
          entityShape[field.name] = getYupValidationForField(field, t_i18n);
        });

        // If entity is required, use regular object validation, otherwise make fields optional
        if (entity.required) {
          shape[`additional_${entity.id}`] = Yup.object().shape(entityShape);
        } else {
          // For optional entities, we don't add validation - fields are optional
          const optionalEntityShape: Record<string, Yup.Schema<unknown>> = {};
          entityFields.forEach((field: FormFieldDefinition) => {
            // Only validate if field is mandatory regardless of entity requirement
            if (field.isMandatory) {
              optionalEntityShape[field.name] = getYupValidationForField(field, t_i18n);
            }
          });
          shape[`additional_${entity.id}`] = Yup.object().shape(optionalEntityShape);
        }
      }
    });
  }

  // Add validation for relationships
  if (schema.relationships && schema.relationships.length > 0) {
    schema.relationships.forEach((relationship) => {
      if (relationship.fields && relationship.fields.length > 0) {
        const relationshipFieldsShape: Record<string, Yup.Schema<unknown>> = {};
        relationship.fields.forEach((field: FormFieldDefinition) => {
          relationshipFieldsShape[field.name] = getYupValidationForField(field, t_i18n);
        });
        shape[`relationship_${relationship.id}`] = Yup.object().shape(relationshipFieldsShape);
      }
    });
  }

  return Yup.object().shape(shape);
};

export const formatFormDataForSubmission = (
  values: Record<string, string | string[] | { value: string } | { value: string }[] | Record<string, unknown> | Record<string, unknown>[]>,
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

  // If main entity lookup is enabled, include the selected entities
  if (schema.mainEntityLookup && values.mainEntityLookup) {
    if (schema.mainEntityMultiple) {
      formattedData.mainEntityLookup = (values.mainEntityLookup as { value: string }[]).map((n) => n.value);
    } else {
      formattedData.mainEntityLookup = (values.mainEntityLookup as { value: string }).value;
    }
  }

  // Handle main entity with field modes
  if (schema.mainEntityMultiple && schema.mainEntityFieldMode === 'parsed') {
    // Parse the text field
    const parsedValues = values.mainEntityParsed as string;
    if (parsedValues) {
      const delimiter = schema.mainEntityParseMode === 'line' ? '\n' : ',';
      formattedData.mainEntityParsed = parsedValues
        .split(delimiter)
        .map((v) => v.trim())
        .filter((v) => v);
    }
    // Also handle additional fields for main entity in parsed mode
    const mainEntityAdditionalFields = values.mainEntityFields as Record<string, unknown>;
    if (mainEntityAdditionalFields) {
      const processedFields: Record<string, unknown> = {};
      const mainEntityFields = schema.fields.filter((field) => field.attributeMapping.entity === 'main_entity');
      mainEntityFields.forEach((field: FormFieldDefinition) => {
        const extractedValue = extractFieldValue(field, mainEntityAdditionalFields[field.name]);
        if (extractedValue !== undefined) {
          // Use the attribute mapping name instead of the field name
          processedFields[field.attributeMapping.attributeName] = extractedValue;
        }
      });
      if (Object.keys(processedFields).length > 0) {
        formattedData.mainEntityFields = processedFields;
      }
    }
  } else if (schema.mainEntityMultiple && schema.mainEntityFieldMode === 'multiple') {
    // Handle field groups
    const groups = values.mainEntityGroups as Record<string, unknown>[];
    formattedData.mainEntityGroups = groups?.map((group) => {
      const processedGroup: Record<string, unknown> = {};
      Object.entries(group).forEach(([fieldName, value]) => {
        const field = schema.fields.find((f) => f.name === fieldName);
        if (field) {
          const extractedValue = extractFieldValue(field, value);
          if (extractedValue !== undefined) {
            processedGroup[fieldName] = extractedValue;
          }
        }
      });
      return processedGroup;
    });
  } else if (!schema.mainEntityLookup) {
    // Process main entity fields (only if not in lookup mode)
    const mainEntityFields = schema.fields.filter((field) => field.attributeMapping.entity === 'main_entity');
    mainEntityFields.forEach((field: FormFieldDefinition) => {
      const extractedValue = extractFieldValue(field, values[field.name]);
      if (extractedValue !== undefined) {
        formattedData[field.name] = extractedValue;
      }
    });
  }

  // Process additional entities
  if (schema.additionalEntities && schema.additionalEntities.length > 0) {
    schema.additionalEntities.forEach((entity) => {
      const entityFields = schema.fields.filter((field) => field.attributeMapping.entity === entity.id);

      if (entity.lookup) {
        // Handle lookup mode
        const lookupValue = values[`additional_${entity.id}_lookup`];
        if (lookupValue) {
          if (entity.multiple) {
            formattedData[`additional_${entity.id}_lookup`] = (lookupValue as { value: string }[]).map((n) => n.value);
          } else {
            formattedData[`additional_${entity.id}_lookup`] = (lookupValue as { value: string }).value;
          }
        }
      } else if (entity.multiple && entity.fieldMode === 'parsed') {
        // Handle parsed mode
        const parsedValues = values[`additional_${entity.id}_parsed`] as string;
        if (parsedValues) {
          const delimiter = entity.parseMode === 'line' ? '\n' : ',';
          formattedData[`additional_${entity.id}_parsed`] = parsedValues
            .split(delimiter)
            .map((v) => v.trim())
            .filter((v) => v);
        }
        // Also handle additional fields for parsed mode
        const additionalFields = values[`additional_${entity.id}_fields`] as Record<string, unknown>;
        if (additionalFields) {
          const processedFields: Record<string, unknown> = {};
          const additionalEntityFields = schema.fields.filter((field) => field.attributeMapping.entity === entity.id);
          additionalEntityFields.forEach((field: FormFieldDefinition) => {
            const extractedValue = extractFieldValue(field, additionalFields[field.name]);
            if (extractedValue !== undefined) {
              // Use the attribute mapping name instead of the field name
              processedFields[field.attributeMapping.attributeName] = extractedValue;
            }
          });
          if (Object.keys(processedFields).length > 0) {
            formattedData[`additional_${entity.id}_fields`] = processedFields;
          }
        }
      } else if (entity.multiple && entity.fieldMode === 'multiple') {
        // Handle field groups
        const groups = values[`additional_${entity.id}_groups`] as Record<string, unknown>[];
        formattedData[`additional_${entity.id}_groups`] = groups?.map((group) => {
          const processedGroup: Record<string, unknown> = {};
          Object.entries(group).forEach(([fieldName, value]) => {
            const field = entityFields.find((f) => f.name === fieldName);
            if (field) {
              const extractedValue = extractFieldValue(field, value);
              if (extractedValue !== undefined) {
                processedGroup[fieldName] = extractedValue;
              }
            }
          });
          return processedGroup;
        });
      } else {
        // Single entity mode
        const entityValues = values[`additional_${entity.id}`] || {};
        entityFields.forEach((field: FormFieldDefinition) => {
          const value = (entityValues as Record<string, unknown>)[field.name];
          const extractedValue = extractFieldValue(field, value);
          if (extractedValue !== undefined) {
            formattedData[field.name] = extractedValue;
          }
        });
      }
    });
  }

  // Process relationships
  if (schema.relationships && schema.relationships.length > 0) {
    const relationshipsData: Record<string, unknown>[] = [];
    schema.relationships.forEach((relationship) => {
      const relationshipData: Record<string, unknown> = {
        id: relationship.id,
        fromEntity: relationship.fromEntity,
        toEntity: relationship.toEntity,
        relationshipType: relationship.relationshipType,
        required: relationship.required,
      };

      // Process relationship fields
      if (relationship.fields && relationship.fields.length > 0) {
        const relationshipFieldsData: Record<string, unknown> = {};
        const relationshipValues = values[`relationship_${relationship.id}`] as Record<string, unknown>;

        if (relationshipValues) {
          relationship.fields.forEach((field: FormFieldDefinition) => {
            const extractedValue = extractFieldValue(field, relationshipValues[field.name]);
            if (extractedValue !== undefined) {
              // Use the attribute mapping name for the field
              relationshipFieldsData[field.attributeMapping.attributeName] = extractedValue;
            }
          });
        }

        if (Object.keys(relationshipFieldsData).length > 0) {
          relationshipData.fields = relationshipFieldsData;
        }
      }

      relationshipsData.push(relationshipData);
    });

    if (relationshipsData.length > 0) {
      formattedData.relationships = relationshipsData;
    }
  }

  return formattedData;
};
