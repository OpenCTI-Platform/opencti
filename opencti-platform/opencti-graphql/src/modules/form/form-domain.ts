import { v4 as uuidv4 } from 'uuid';
import Ajv from 'ajv';
import type { FileHandle } from 'fs/promises';
import { createEntity, deleteElementById, patchAttribute, updateAttribute } from '../../database/middleware';
import { fullEntitiesList, internalLoadById, pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import type { BasicStoreEntityForm, FormFieldDefinition, FormSchemaDefinition, StoreEntityForm } from './form-types';
import { ENTITY_TYPE_FORM, FormSchemaDefinitionSchema } from './form-types';
import type { AuthContext, AuthUser } from '../../types/user';
import { FunctionalError } from '../../config/errors';
import { connectorIdFromIngestId, registerConnectorForIngestion, unregisterConnectorForIngestion } from '../../domain/connector';
import { publishUserAction } from '../../listener/UserActionListener';
import { generateStandardId } from '../../schema/identifier';
import { logApp } from '../../config/conf';
import { pushToWorkerForConnector } from '../../database/rabbitmq';
import { createWork, updateExpectationsNumber } from '../../domain/work';
import { ConnectorPriorityGroup, ConnectorType, FilterMode, type FormSubmissionInput } from '../../generated/graphql';
import { now, nowTime } from '../../utils/format';
import { SYSTEM_USER } from '../../utils/access';
import { convertStoreToStix_2_1 } from '../../database/stix-2-1-converter';
import { addDraftWorkspace } from '../draftWorkspace/draftWorkspace-domain';
import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixId } from '../../types/stix-2-1-common';
import { isEmptyField, isNotEmptyField } from '../../database/utils';
import { ENTITY_TYPE_MALWARE, isStixDomainObject, isStixDomainObjectContainer } from '../../schema/stixDomainObject';
import type { StixRelation } from '../../types/stix-2-1-sro';
import type { StixContainer } from '../../types/stix-2-1-sdo';
import { ENTITY_TYPE_CONTAINER_GROUPING } from '../grouping/grouping-types';
import { detectObservableType } from '../../utils/observable';
import { createStixPattern } from '../../python/pythonBridge';
import pjson from '../../../package.json';
import { extractContentFrom } from '../../utils/fileToContent';
import { addFormIntakeCreatedCount, addFormIntakeDeletedCount, addFormIntakeSubmittedCount, addFormIntakeUpdatedCount } from '../../manager/telemetryManager';

const ajv = new Ajv();
const validateSchema = ajv.compile(FormSchemaDefinitionSchema);

export const addForm = async (
  context: AuthContext,
  user: AuthUser,
  input: any
): Promise<BasicStoreEntityForm> => {
  let parsedSchema: FormSchemaDefinition;
  try {
    parsedSchema = JSON.parse(input.form_schema);
  } catch (error) {
    throw FunctionalError(`Invalid JSON in form_schema: ${error}`);
  }

  const isValid = validateSchema(parsedSchema);
  if (!isValid) {
    throw FunctionalError(`Invalid form schema: ${JSON.stringify(validateSchema.errors)}`);
  }

  // Check for duplicate form names with the same main entity type
  const existingForms = await fullEntitiesList(context, user, ['Form'], {
    filters: {
      mode: FilterMode.And,
      filters: [
        { key: ['name'], values: [input.name] },
        { key: ['main_entity_type'], values: [parsedSchema.mainEntityType] },
      ],
      filterGroups: [],
    },
  });

  if (existingForms.length > 0) {
    throw FunctionalError(`A form with the name "${input.name}" already exists for entity type "${parsedSchema.mainEntityType}"`);
  }

  const formToCreate: Partial<BasicStoreEntityForm> = {
    name: input.name,
    description: input.description,
    main_entity_type: parsedSchema.mainEntityType,
    form_schema: input.form_schema, // Store as JSON string
    active: input.active ?? true,
  };

  const { element, isCreation } = await createEntity(
    context,
    user,
    formToCreate,
    ENTITY_TYPE_FORM,
    { complete: true }
  );

  if (isCreation) {
    await registerConnectorForIngestion(context, {
      id: element.id,
      type: 'FORM',
      name: element.name,
      is_running: element.active ?? false,
      connector_user_id: user.id,
      connector_priority_group: ConnectorPriorityGroup.Realtime,
    });

    await publishUserAction({
      user,
      event_type: 'mutation',
      event_scope: 'create',
      event_access: 'administration',
      message: `creates form intake \`${input.name}\``,
      context_data: { id: element.id, entity_type: ENTITY_TYPE_FORM, input: { name: input.name, mainEntityType: parsedSchema.mainEntityType } },
    });

    // Add telemetry
    await addFormIntakeCreatedCount();
  }

  return element;
};

export const findById = async (
  context: AuthContext,
  user: AuthUser,
  formId: string
): Promise<BasicStoreEntityForm> => {
  return storeLoadById<BasicStoreEntityForm>(context, user, formId, ENTITY_TYPE_FORM);
};

export const findFormPaginated = async (
  context: AuthContext,
  user: AuthUser,
  opts = {}
) => {
  return pageEntitiesConnection<BasicStoreEntityForm>(context, user, [ENTITY_TYPE_FORM], opts);
};

export const findAllForms = async (
  context: AuthContext,
  user: AuthUser,
  opts = {}
) => {
  return fullEntitiesList<BasicStoreEntityForm>(context, user, [ENTITY_TYPE_FORM], opts);
};

export const patchForm = async (
  context: AuthContext,
  user: AuthUser,
  id: string,
  patch: object
) => {
  const patched = await patchAttribute(context, user, id, ENTITY_TYPE_FORM, patch);
  return patched.element;
};

export const formEditField = async (
  context: AuthContext,
  user: AuthUser,
  formId: string,
  input: { key: string; value: string | string[] | null }[]
): Promise<StoreEntityForm> => {
  const updates = input.map(({ key, value }) => {
    // If updating the form_schema, validate it first
    if (key === 'form_schema' && value) {
      try {
        const parsedSchema = JSON.parse(value as string);
        const isValid = validateSchema(parsedSchema);
        if (!isValid) {
          throw FunctionalError(`Invalid form schema: ${JSON.stringify(validateSchema.errors)}`);
        }
      } catch (error) {
        if (error instanceof FunctionalError) throw error;
        throw FunctionalError(`Invalid JSON in form_schema: ${error}`);
      }
    }
    return { key, value: Array.isArray(value) ? value : [value] };
  });

  const { element } = await updateAttribute(context, user, formId, ENTITY_TYPE_FORM, updates);

  // Update connector registration
  const activeUpdate = input.find(({ key }) => key === 'active');
  if (activeUpdate) {
    const isActive = activeUpdate.value === 'true' || (Array.isArray(activeUpdate.value) && activeUpdate.value[0] === 'true');
    await registerConnectorForIngestion(context, {
      id: element.id,
      type: 'FORM',
      name: element.name,
      is_running: isActive,
      connector_user_id: user.id
    });
  }

  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates form intake \`${element.name}\``,
    context_data: { id: formId, entity_type: ENTITY_TYPE_FORM, input: { name: element.name } }
  });

  // Add telemetry
  await addFormIntakeUpdatedCount();

  return element;
};

export const formDelete = async (
  context: AuthContext,
  user: AuthUser,
  formId: string
) => {
  // Get form details before deletion for the user action message
  const form = await findById(context, user, formId);

  // Unregister connector before deletion
  await unregisterConnectorForIngestion(context, formId);

  // Delete the form entity
  await deleteElementById(context, user, formId, ENTITY_TYPE_FORM);

  // Publish user action
  if (form) {
    await publishUserAction({
      user,
      event_type: 'mutation',
      event_scope: 'delete',
      event_access: 'administration',
      message: `deletes form intake \`${form.name}\``,
      context_data: { id: formId, entity_type: ENTITY_TYPE_FORM, input: { name: form.name } }
    });

    // Add telemetry
    await addFormIntakeDeletedCount();
  }

  return formId;
};

export interface FormParsed extends Omit<StoreEntityForm, 'form_schema'> {
  form_schema: FormSchemaDefinition;
}

// Helper function to transform special fields for STIX conversion (entities and relationships)
// Helper function to convert string values to proper types based on field type
const convertFieldType = (value: any, field: FormFieldDefinition): any => {
  // Don't convert if already the right type or if value is null/undefined
  if (isEmptyField(value)) {
    return value;
  }

  // Handle boolean fields
  if (field.type === 'checkbox' || field.type === 'toggle') {
    if (typeof value === 'string') {
      return value === 'true' || value === '1';
    }
    return Boolean(value);
  }

  // Handle number fields
  if (field.type === 'number') {
    if (typeof value === 'string') {
      const num = Number(value);
      return Number.isNaN(num) ? value : num;
    }
    return value;
  }

  // For other types, return as-is
  return value;
};

const transformSpecialFields = async (
  context: AuthContext,
  user: AuthUser,
  data: any,
  fields: FormFieldDefinition[],
  isRelationship: boolean = false
): Promise<any> => {
  const transformed = { ...data };

  // For relationships, the field values come from the 'fields' property
  const fieldsSource = isRelationship && data.fields ? data.fields : data;

  // Find special fields that need transformation
  // eslint-disable-next-line no-restricted-syntax
  for (const field of fields) {
    const attrName = field.attributeMapping.attributeName;
    const value = (fieldsSource as any)[attrName];

    if (!value) {
      // eslint-disable-next-line no-continue
      continue;
    }

    if (field.type === 'createdBy' && typeof value === 'string') {
      // Transform createdBy from internal_id
      const createdByEntity = await internalLoadById(context, user, value);
      if (createdByEntity) {
        if (isRelationship) {
          // For relationships, use STIX ref format
          transformed.created_by_ref = createdByEntity.standard_id;
        } else {
          // For entities, use object format
          (transformed as any).createdBy = {
            internal_id: createdByEntity.internal_id,
            standard_id: createdByEntity.standard_id
          };
        }
      }
    } else if (field.type === 'objectMarking' && Array.isArray(value)) {
      // Transform objectMarking from array of internal_ids
      const markings = [];
      // eslint-disable-next-line no-restricted-syntax
      for (const markingId of value) {
        if (typeof markingId === 'string') {
          const markingEntity = await internalLoadById(context, user, markingId);
          if (markingEntity) {
            if (isRelationship) {
              // For relationships, just collect standard_ids
              markings.push(markingEntity.standard_id);
            } else {
              // For entities, use object format
              markings.push({
                internal_id: markingEntity.internal_id,
                standard_id: markingEntity.standard_id
              });
            }
          }
        }
      }
      if (isRelationship) {
        transformed.object_marking_refs = markings;
      } else {
        (transformed as any).objectMarking = markings;
      }
    } else if (field.type === 'objectLabel' && Array.isArray(value)) {
      // Transform labels
      if (isRelationship) {
        transformed.labels = value; // For relationships, labels are simple strings
      } else {
        (transformed as any).objectLabel = value.map((label: any) => ({ value: label }));
      }
    } else if (field.type === 'files' && Array.isArray(value)) {
      // Transform files to x_opencti_files format
      // Files should come as array of { name: string, data: string } where data is base64 encoded
      const files = value.map((file: any) => ({
        name: file.name,
        data: file.data, // base64 encoded content
        mime_type: file.mime_type || 'application/octet-stream',
      }));
      if (!isRelationship) {
        (transformed as any).x_opencti_files = files;
      }
    } else if (field.type === 'externalReferences' && Array.isArray(value)) {
      // Transform external references
      const references = [];
      // eslint-disable-next-line no-restricted-syntax
      for (const refId of value) {
        if (typeof refId === 'string') {
          const refEntity = await internalLoadById(context, user, refId);
          if (refEntity) {
            references.push(refEntity);
          }
        }
      }
      (transformed as any).externalReferences = references;
    } else if (isRelationship && attrName && value !== undefined) {
      // For relationships, apply other fields directly
      transformed[attrName] = value;
    }
  }

  // For relationships, remove the fields object after processing
  if (isRelationship) {
    delete transformed.fields;
  }

  return transformed;
};

const completeEntity = (entityType: string, entity: StoreEntity) => {
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
  }
  finalEntity.id = finalEntity.internal_id;
  return finalEntity;
};

// Submit a form and convert to STIX bundle
export const formSubmit = async (
  context: AuthContext,
  user: AuthUser,
  input: FormSubmissionInput,
  isDraft: boolean = false
): Promise<any> => {
  const form = await findById(context, user, input.formId);
  if (!form) {
    throw FunctionalError('Form not found', { id: input.formId });
  }

  let values = {} as Record<string, any>;
  try {
    values = JSON.parse(input.values);
  } catch (error) {
    throw FunctionalError('Cannot read values', { error });
  }

  const schema: FormSchemaDefinition = JSON.parse(form.form_schema);
  const errors: string[] = [];

  // Enforce draft settings from schema
  let finalIsDraft = isDraft;
  if (schema.isDraftByDefault === true) {
    if (schema.allowDraftOverride === false) {
      finalIsDraft = true;
    }
  }

  // Validation
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
    // Validate additional fields in parsed mode
    if (values.mainEntityFields) {
      schema.fields.filter((field) => field.attributeMapping.entity === 'main_entity').forEach((field) => {
        if (field.isMandatory || field.required) {
          const fieldValue = values.mainEntityFields[field.attributeMapping.attributeName];
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
        // Validate additional fields in parsed mode
        if (values[`additional_${additionalEntity.id}_fields`]) {
          schema.fields.filter((field) => field.attributeMapping.entity === additionalEntity.id).forEach((field) => {
            if (field.isMandatory || field.required) {
              const fieldValue = values[`additional_${additionalEntity.id}_fields`][field.attributeMapping.attributeName];
              if (isEmptyField(fieldValue)) {
                errors.push(`Required field "${field.label || field.name}" is missing`);
              }
            }
          });
        }
      }
      if (!additionalEntity.lookup && !additionalEntity.multiple) {
        // Only validate mandatory fields if the entity is required or if at least one field is filled
        const entityFields = schema.fields.filter((field) => field.attributeMapping.entity === additionalEntity.id);
        const entityData = values[`additional_${additionalEntity.id}`];

        // Check if entity data exists and has any meaningful content
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

  // Create the bundle structure
  const bundle: any = {
    type: 'bundle',
    id: `bundle--${uuidv4()}`,
    spec_version: '2.1',
    objects: []
  };

  // Create main entity
  const mainStixEntities = [];
  const { mainEntityType } = schema;
  let mainEntityStixId;
  if (schema.mainEntityLookup) {
    const vals = Array.isArray(values.mainEntityLookup) ? values.mainEntityLookup : [values.mainEntityLookup];
    const mainEntities = await Promise.all(vals.map((id: string) => {
      return storeLoadById<StoreEntityForm>(context, user, id, mainEntityType);
    }));
    for (let index = 0; index < mainEntities.length; index += 1) {
      mainStixEntities.push(convertStoreToStix_2_1(mainEntities[index]));
      mainEntityStixId = mainEntities[index].standard_id;
    }
  } else {
    const mainEntityFields = schema.fields.filter((field) => field.attributeMapping.entity === 'main_entity');
    if (schema.mainEntityMultiple && schema.mainEntityFieldMode === 'multiple') {
      for (let index = 0; index < values.mainEntityGroups.length; index += 1) {
        let mainEntity = { entity_type: mainEntityType } as StoreEntity;
        for (let i = 0; i < mainEntityFields.length; i += 1) {
          const field = mainEntityFields[i];
          const fieldValue = values.mainEntityGroups[index][field.name];
          // Convert the field value to the correct type
          const convertedValue = convertFieldType(fieldValue, field);
          // eslint-disable-next-line @typescript-eslint/ban-ts-comment
          // @ts-expect-error
          mainEntity[field.attributeMapping.attributeName] = convertedValue;
        }
        mainEntity = completeEntity(mainEntityType, mainEntity);
        mainStixEntities.push(convertStoreToStix_2_1(mainEntity));
        mainEntityStixId = mainEntity.standard_id;
      }
    } else if (schema.mainEntityMultiple && schema.mainEntityFieldMode === 'parsed') {
      for (let index = 0; index < values.mainEntityParsed.length; index += 1) {
        let mainEntity = { entity_type: mainEntityType } as StoreEntity;
        if (schema.mainEntityParseFieldMapping === 'pattern' && schema.mainEntityAutoConvertToStixPattern) {
          // Auto convert the value
          const observableType = detectObservableType(values.mainEntityParsed[index]);
          const observableValue = values.mainEntityParsed[index];
          const pattern = await createStixPattern(context, user, observableType, observableValue);
          mainEntity[schema.mainEntityParseFieldMapping] = pattern;
          mainEntity.pattern_type = 'stix';
          mainEntity.name = observableValue;
          mainEntity.x_opencti_main_observable_type = observableType;
        } else {
          // eslint-disable-next-line @typescript-eslint/ban-ts-comment
          // @ts-expect-error
          mainEntity[schema.mainEntityParseFieldMapping] = values.mainEntityParsed[index];
        }

        // Apply additional fields to all parsed entities
        if (values.mainEntityFields) {
          const additionalMainEntityFields = schema.fields.filter((field) => field.attributeMapping.entity === 'main_entity');
          for (let i = 0; i < additionalMainEntityFields.length; i += 1) {
            const field = additionalMainEntityFields[i];
            const fieldValue = values.mainEntityFields[field.attributeMapping.attributeName];
            if (fieldValue !== undefined && fieldValue !== null && fieldValue !== '') {
              // Convert the field value to the correct type
              const convertedValue = convertFieldType(fieldValue, field);
              // eslint-disable-next-line @typescript-eslint/ban-ts-comment
              // @ts-expect-error
              mainEntity[field.attributeMapping.attributeName] = convertedValue;
            }
          }
          // Transform special fields after applying all field values
          mainEntity = await transformSpecialFields(context, user, mainEntity, additionalMainEntityFields, false);
        }

        if (mainEntityType === ENTITY_TYPE_MALWARE && isEmptyField(mainEntity.is_family)) {
          mainEntity.is_family = true;
        }
        if (mainEntityType === ENTITY_TYPE_CONTAINER_GROUPING && isEmptyField(mainEntity.context)) {
          mainEntity.context = 'form';
        }
        mainEntity = completeEntity(mainEntityType, mainEntity);
        mainStixEntities.push(convertStoreToStix_2_1(mainEntity));
        mainEntityStixId = mainEntity.standard_id;
      }
    } else {
      let mainEntity = { entity_type: mainEntityType } as StoreEntity;
      for (let i = 0; i < mainEntityFields.length; i += 1) {
        const field = mainEntityFields[i];
        const fieldValue = values[field.name];
        // Convert the field value to the correct type
        const convertedValue = convertFieldType(fieldValue, field);
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-expect-error
        mainEntity[field.attributeMapping.attributeName] = convertedValue;
      }
      // Transform special fields after applying all field values
      mainEntity = await transformSpecialFields(context, user, mainEntity, mainEntityFields, false);
      mainEntity = completeEntity(mainEntityType, mainEntity);
      mainStixEntities.push(convertStoreToStix_2_1(mainEntity));
      mainEntityStixId = mainEntity.standard_id;
    }
  }

  // Create additional entities
  const additionalEntitiesMap: Record<string, string[]> = {};
  if (schema.additionalEntities) {
    for (let index = 0; index < schema.additionalEntities.length; index += 1) {
      const additionalEntity = schema.additionalEntities[index];
      const additionalEntityType = additionalEntity.entityType;
      if (additionalEntity.lookup) {
        if (isNotEmptyField(values[`additional_${additionalEntity.id}_lookup`])) {
          const vals = Array.isArray(values[`additional_${additionalEntity.id}_lookup`]) ? values[`additional_${additionalEntity.id}_lookup`] : [values[`additional_${additionalEntity.id}_lookup`]];
          const additionalEntities = await Promise.all(vals.map((id: string) => {
            return storeLoadById<StoreEntityForm>(context, user, id, additionalEntityType);
          }));
          for (let index2 = 0; index2 < additionalEntities.length; index2 += 1) {
            const stixAdditionalEntity = convertStoreToStix_2_1(additionalEntities[index2]);
            bundle.objects.push(stixAdditionalEntity);
            if (additionalEntitiesMap[additionalEntity.id]) {
              additionalEntitiesMap[additionalEntity.id].push(stixAdditionalEntity.id);
            } else {
              additionalEntitiesMap[additionalEntity.id] = [stixAdditionalEntity.id];
            }
          }
        }
      } else {
        const additionalEntityFields = schema.fields.filter((field) => field.attributeMapping.entity === additionalEntity.id);
        if (additionalEntity.multiple && additionalEntity.fieldMode === 'multiple') {
          if (isNotEmptyField(values[`additional_${additionalEntity.id}_groups`])) {
            for (let index2 = 0; index2 < values[`additional_${additionalEntity.id}_groups`].length; index2 += 1) {
              let newAdditionalEntity = { entity_type: additionalEntityType } as StoreEntity;
              for (let i = 0; i < additionalEntityFields.length; i += 1) {
                const field = additionalEntityFields[i];
                const fieldValue = values[`additional_${additionalEntity.id}_groups`][index2][field.name];
                // Convert the field value to the correct type
                const convertedValue = convertFieldType(fieldValue, field);
                // eslint-disable-next-line @typescript-eslint/ban-ts-comment
                // @ts-expect-error
                newAdditionalEntity[field.attributeMapping.attributeName] = convertedValue;
              }
              newAdditionalEntity = completeEntity(additionalEntityType, newAdditionalEntity);
              const stixAdditionalEntity = convertStoreToStix_2_1(newAdditionalEntity);
              bundle.objects.push(stixAdditionalEntity);
              if (additionalEntitiesMap[additionalEntity.id]) {
                additionalEntitiesMap[additionalEntity.id].push(stixAdditionalEntity.id);
              } else {
                additionalEntitiesMap[additionalEntity.id] = [stixAdditionalEntity.id];
              }
            }
          }
        } else if (additionalEntity.multiple && additionalEntity.fieldMode === 'parsed') {
          if (isNotEmptyField(values[`additional_${additionalEntity.id}_parsed`])) {
            for (let index2 = 0; index2 < values[`additional_${additionalEntity.id}_parsed`].length; index2 += 1) {
              let newAdditionalEntity = { entity_type: additionalEntityType } as StoreEntity;
              if (additionalEntity.parseFieldMapping === 'pattern' && additionalEntity.autoConvertToStixPattern) {
                // Auto convert the value
                const observableType = detectObservableType(values[`additional_${additionalEntity.id}_parsed`][index2]);
                const observableValue = values[`additional_${additionalEntity.id}_parsed`][index2];
                const pattern = await createStixPattern(context, user, observableType, observableValue);
                newAdditionalEntity[additionalEntity.parseFieldMapping] = pattern;
                newAdditionalEntity.pattern_type = 'stix';
                newAdditionalEntity.name = observableValue;
                newAdditionalEntity.x_opencti_main_observable_type = observableType;
              } else {
                // eslint-disable-next-line @typescript-eslint/ban-ts-comment
                // @ts-expect-error
                newAdditionalEntity[additionalEntity.parseFieldMapping] = values[`additional_${additionalEntity.id}_parsed`][index2];
              }

              // Apply additional fields to all parsed entities
              if (values[`additional_${additionalEntity.id}_fields`]) {
                for (let i = 0; i < additionalEntityFields.length; i += 1) {
                  const field = additionalEntityFields[i];
                  const fieldValue = values[`additional_${additionalEntity.id}_fields`][field.attributeMapping.attributeName];
                  if (fieldValue !== undefined && fieldValue !== null && fieldValue !== '') {
                    // Convert the field value to the correct type
                    const convertedValue = convertFieldType(fieldValue, field);
                    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
                    // @ts-expect-error
                    newAdditionalEntity[field.attributeMapping.attributeName] = convertedValue;
                  }
                }
                // Transform special fields after applying all field values
                newAdditionalEntity = await transformSpecialFields(context, user, newAdditionalEntity, additionalEntityFields, false);
              }

              if (additionalEntityType === ENTITY_TYPE_MALWARE && isEmptyField(newAdditionalEntity.is_family)) {
                newAdditionalEntity.is_family = true;
              }
              if (additionalEntityType === ENTITY_TYPE_CONTAINER_GROUPING && isEmptyField(newAdditionalEntity.context)) {
                newAdditionalEntity.context = 'form';
              }
              newAdditionalEntity = completeEntity(additionalEntityType, newAdditionalEntity);
              const stixAdditionalEntity = convertStoreToStix_2_1(newAdditionalEntity);
              bundle.objects.push(stixAdditionalEntity);
              if (additionalEntitiesMap[additionalEntity.id]) {
                additionalEntitiesMap[additionalEntity.id].push(stixAdditionalEntity.id);
              } else {
                additionalEntitiesMap[additionalEntity.id] = [stixAdditionalEntity.id];
              }
            }
          }
        } else {
          // Single entity mode - check if data exists under the properly namespaced key
          const entityData = values[`additional_${additionalEntity.id}`];

          // Only process if we have entity data and it's either required or has meaningful content
          if (entityData && typeof entityData === 'object') {
            // Check if any field has meaningful content
            const hasAnyFieldFilled = additionalEntityFields.some((field) => {
              const value = entityData[field.name];
              return isNotEmptyField(value);
            });

            if (additionalEntity.required || hasAnyFieldFilled) {
              let newAdditionalEntity = { entity_type: additionalEntityType } as StoreEntity;
              for (let i = 0; i < additionalEntityFields.length; i += 1) {
                const field = additionalEntityFields[i];
                const fieldValue = entityData[field.name];

                if (fieldValue !== undefined && fieldValue !== null && fieldValue !== '') {
                  // Convert the field value to the correct type
                  const convertedValue = convertFieldType(fieldValue, field);
                  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
                  // @ts-expect-error
                  newAdditionalEntity[field.attributeMapping.attributeName] = convertedValue;
                }
              }

              // Transform special fields (e.g., createdBy, objectMarking)
              newAdditionalEntity = await transformSpecialFields(context, user, newAdditionalEntity, additionalEntityFields, false);

              // Set defaults for specific entity types if needed
              if (additionalEntityType === ENTITY_TYPE_MALWARE && isEmptyField(newAdditionalEntity.is_family)) {
                newAdditionalEntity.is_family = true;
              }
              if (additionalEntityType === ENTITY_TYPE_CONTAINER_GROUPING && isEmptyField(newAdditionalEntity.context)) {
                newAdditionalEntity.context = 'form';
              }

              newAdditionalEntity = completeEntity(additionalEntityType, newAdditionalEntity);
              const stixAdditionalEntity = convertStoreToStix_2_1(newAdditionalEntity);
              bundle.objects.push(stixAdditionalEntity);
              if (additionalEntitiesMap[additionalEntity.id]) {
                additionalEntitiesMap[additionalEntity.id].push(stixAdditionalEntity.id);
              } else {
                additionalEntitiesMap[additionalEntity.id] = [stixAdditionalEntity.id];
              }
            }
          }
        }
      }
    }
  }

  // Create relationships
  if (schema.relationships && schema.relationships.length > 0 && values.relationships) {
    for (let i = 0; i < schema.relationships.length; i += 1) {
      const rel = schema.relationships[i];
      // Find the relationship data from submitted values
      const submittedRel = (values.relationships as any[])?.find((r: any) => r.id === rel.id);
      if (rel.fromEntity === 'main_entity') {
        for (let j = 0; j < mainStixEntities.length; j += 1) {
          for (let k = 0; k < (additionalEntitiesMap[rel.toEntity] ?? []).length; k += 1) {
            let relationshipData: Partial<StixRelation> = {
              id: `relationship--${uuidv4()}`,
              type: 'relationship',
              spec_version: '2.1',
              created: new Date().toISOString(),
              modified: new Date().toISOString(),
              relationship_type: rel.relationshipType,
              source_ref: mainStixEntities[j].id,
              target_ref: additionalEntitiesMap[rel.toEntity][k]
            };
            // Apply additional fields from submitted data
            if (submittedRel?.fields && rel.fields) {
              // Transform and apply relationship fields
              relationshipData = await transformSpecialFields(context, user, { ...relationshipData, fields: submittedRel.fields }, rel.fields, true);
            }
            bundle.objects.push(relationshipData);
          }
        }
      } else if (rel.toEntity === 'main_entity') {
        for (let j = 0; j < mainStixEntities.length; j += 1) {
          for (let k = 0; k < (additionalEntitiesMap[rel.fromEntity] ?? []).length; k += 1) {
            let relationshipData: Partial<StixRelation> = {
              id: `relationship--${uuidv4()}`,
              type: 'relationship',
              spec_version: '2.1',
              created: new Date().toISOString(),
              modified: new Date().toISOString(),
              relationship_type: rel.relationshipType,
              source_ref: additionalEntitiesMap[rel.fromEntity][k],
              target_ref: mainStixEntities[j].id
            };
            // Apply additional fields from submitted data
            if (submittedRel?.fields && rel.fields) {
              // Transform and apply relationship fields
              relationshipData = await transformSpecialFields(context, user, { ...relationshipData, fields: submittedRel.fields }, rel.fields, true);
            }
            bundle.objects.push(relationshipData);
          }
        }
      } else {
        for (let j = 0; j < (additionalEntitiesMap[rel.fromEntity] ?? []).length; j += 1) {
          for (let k = 0; k < (additionalEntitiesMap[rel.toEntity] ?? []).length; k += 1) {
            let relationshipData: Partial<StixRelation> = {
              id: `relationship--${uuidv4()}`,
              type: 'relationship',
              spec_version: '2.1',
              created: new Date().toISOString(),
              modified: new Date().toISOString(),
              relationship_type: rel.relationshipType,
              source_ref: additionalEntitiesMap[rel.fromEntity][j],
              target_ref: additionalEntitiesMap[rel.toEntity][k]
            };
            // Apply additional fields from submitted data
            if (submittedRel?.fields && rel.fields) {
              // Transform and apply relationship fields
              relationshipData = await transformSpecialFields(context, user, { ...relationshipData, fields: submittedRel.fields }, rel.fields, true);
            }
            bundle.objects.push(relationshipData);
          }
        }
      }
    }
  }

  // Add to containers
  if (schema.includeInContainer && isStixDomainObjectContainer(mainEntityType)) {
    for (let i = 0; i < mainStixEntities.length; i += 1) {
      const stixContainer = mainStixEntities[i] as StixContainer;
      stixContainer.object_refs = bundle.objects.map((n: BasicStoreEntity) => n.id);
      bundle.objects.push(stixContainer);
    }
  } else {
    for (let i = 0; i < mainStixEntities.length; i += 1) {
      bundle.objects.push(mainStixEntities[i]);
    }
  }

  // Log the full STIX bundle before sending
  logApp.info('[FORM] STIX Bundle generated', { bundleId: bundle.id, objectCount: bundle.objects.length, bundle });

  try {
    const connectorId = connectorIdFromIngestId(form.id);
    const connector = { internal_id: connectorId, connector_type: ConnectorType.ExternalImport };
    const workName = `Form submission @ ${now()}`;
    const work: any = await createWork(context, SYSTEM_USER, connector, workName, connector.internal_id, { receivedTime: now() });

    const stixBundle = JSON.stringify(bundle);
    const content = Buffer.from(stixBundle, 'utf-8').toString('base64');

    if (bundle.objects.length > 0) {
      await updateExpectationsNumber(context, SYSTEM_USER, work.id, bundle.objects.length);
    }

    let draftId = null;
    if (finalIsDraft) {
      const draft = await addDraftWorkspace(context, user, { name: `${form.name} - ${nowTime()}` });
      draftId = draft.id;
    }
    await pushToWorkerForConnector(connectorId, {
      type: 'bundle',
      applicant_id: user.id,
      content,
      work_id: work.id,
      draft_id: draftId,
      update: true
    });

    logApp.info('[FORM] Bundle sent to connector queue', { formId: form.id, workId: work.id, bundleId: bundle.id });

    // Add telemetry for form submission
    await addFormIntakeSubmittedCount();

    return {
      success: true,
      bundleId: bundle.id,
      message: 'Form submitted successfully and sent for processing',
      entityId: finalIsDraft ? draftId : mainEntityStixId
    };
  } catch (error) {
    logApp.error('[FORM] Error sending bundle to connector queue', { error });
    throw FunctionalError('Failed to process form submission', { cause: error });
  }
};

// Export and Import functionality
export const generateFormExportConfiguration = async (
  context: AuthContext,
  user: AuthUser,
  form: BasicStoreEntityForm,
) => {
  const exportConfiguration = {
    openCTI_version: pjson.version,
    type: 'form',
    configuration: {
      name: form.name,
      description: form.description,
      form_schema: form.form_schema,
      active: form.active,
    },
  };
  return JSON.stringify(exportConfiguration);
};

export const importFormConfiguration = async (
  context: AuthContext,
  user: AuthUser,
  file: Promise<FileHandle>
) => {
  const parsedData = await extractContentFrom(file);
  if (parsedData.type !== 'form') {
    throw FunctionalError('Invalid import file type', { expected: 'form', received: parsedData.type });
  }
  const { configuration } = parsedData;
  // Create a new form with the imported configuration
  const formToCreate = {
    name: configuration.name,
    description: configuration.description || '',
    form_schema: configuration.form_schema,
    active: configuration.active !== undefined ? configuration.active : true,
  };
  const createdForm = await addForm(context, user, formToCreate);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: 'administration',
    message: `imports form \`${createdForm.name}\``,
    context_data: { id: createdForm.id, entity_type: ENTITY_TYPE_FORM, input: formToCreate }
  });
  return createdForm;
};
