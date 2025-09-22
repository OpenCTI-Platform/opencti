import { v4 as uuidv4 } from 'uuid';
import Ajv from 'ajv';
import { createEntity, deleteElementById, patchAttribute, updateAttribute } from '../../database/middleware';
import { fullEntitiesList, pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import type { BasicStoreEntityForm, FormSchemaDefinition, FormSubmissionData, StoreEntityForm } from './form-types';
import { ENTITY_TYPE_FORM, FormSchemaDefinitionSchema } from './form-types';
import type { AuthContext, AuthUser } from '../../types/user';
import { FunctionalError } from '../../config/errors';
import { connectorIdFromIngestId, registerConnectorForIngestion, unregisterConnectorForIngestion } from '../../domain/connector';
import { publishUserAction } from '../../listener/UserActionListener';
import { generateStandardId } from '../../schema/identifier';
import { logApp } from '../../config/conf';
import { pushToWorkerForConnector } from '../../database/rabbitmq';
import { createWork, updateExpectationsNumber } from '../../domain/work';
import { ConnectorType } from '../../generated/graphql';
import { now } from '../../utils/format';
import { SYSTEM_USER } from '../../utils/access';
import { convertStoreToStix } from '../../database/stix-2-1-converter';
import { addDraftWorkspace } from '../draftWorkspace/draftWorkspace-domain';
import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixId } from '../../types/stix-2-1-common';
import { isEmptyField } from '../../database/utils';
import { ENTITY_TYPE_MALWARE, isStixDomainObject, isStixDomainObjectContainer, isStixObjectAliased } from '../../schema/stixDomainObject';
import type { StixRelation } from '../../types/stix-2-1-sro';
import type { StixContainer } from '../../types/stix-2-1-sdo';
import { ENTITY_TYPE_CONTAINER_GROUPING } from '../grouping/grouping-types';

const ajv = new Ajv();
const validateSchema = ajv.compile(FormSchemaDefinitionSchema);

// CRUD operations
export const addForm = async (
  context: AuthContext,
  user: AuthUser,
  input: any
): Promise<BasicStoreEntityForm> => {
  // Parse and validate the JSON schema
  let parsedSchema: FormSchemaDefinition;
  try {
    parsedSchema = JSON.parse(input.form_schema);
  } catch (error) {
    // eslint-disable-next-line @typescript-eslint/no-throw-literal
    throw FunctionalError(`Invalid JSON in form_schema: ${error}`);
  }

  const isValid = validateSchema(parsedSchema);
  if (!isValid) {
    throw FunctionalError(`Invalid form schema: ${JSON.stringify(validateSchema.errors)}`);
  }

  // Create the form entity
  const formToCreate: Partial<BasicStoreEntityForm> = {
    name: input.name,
    description: input.description,
    main_entity_type: parsedSchema.mainEntityType,
    form_schema: input.form_schema, // Store as JSON string
    active: input.active ?? true,
  };

  // Create entity following the ingestion pattern
  const { element, isCreation } = await createEntity(
    context,
    user,
    formToCreate,
    ENTITY_TYPE_FORM,
    { complete: true }
  );

  if (isCreation) {
    // Register connector for this form ingestion
    await registerConnectorForIngestion(context, {
      id: element.id,
      type: 'FORM',
      name: element.name,
      is_running: element.active ?? false,
      connector_user_id: user.id
    });

    // Publish user action
    await publishUserAction({
      user,
      event_type: 'mutation',
      event_scope: 'create',
      event_access: 'administration',
      message: `creates form intake \`${input.name}\``,
      context_data: { id: element.id, entity_type: ENTITY_TYPE_FORM, input: { name: input.name, mainEntityType: parsedSchema.mainEntityType } },
    });
  }

  return element;
};

export const findById = async (
  context: AuthContext,
  user: AuthUser,
  formId: string
): Promise<StoreEntityForm> => {
  const form = await storeLoadById<StoreEntityForm>(context, user, formId, ENTITY_TYPE_FORM);
  return form;
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
        // eslint-disable-next-line @typescript-eslint/no-throw-literal
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

  return element;
};

export const formDelete = async (
  context: AuthContext,
  user: AuthUser,
  formId: string
): Promise<boolean> => {
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
  }

  return true;
};

export interface FormParsed extends Omit<StoreEntityForm, 'form_schema'> {
  form_schema: FormSchemaDefinition;
}

const completeEntity = (entityType: string, entity: StoreEntity) => {
  const finalEntity = entity;
  finalEntity.standard_id = generateStandardId(entityType, entity) as StixId;
  finalEntity.internal_id = uuidv4();
  if (isStixDomainObject(entityType)) {
    finalEntity.created = new Date();
    finalEntity.modified = new Date();
  }
  finalEntity.id = finalEntity.internal_id;
  return finalEntity;
};

// Submit a form and convert to STIX bundle
export const submitForm = async (
  context: AuthContext,
  user: AuthUser,
  submission: FormSubmissionData,
  isDraft: boolean = false
): Promise<any> => {
  const form = await findById(context, user, submission.formId);
  if (!form) {
    throw FunctionalError('Form not found');
  }

  const schema: FormSchemaDefinition = JSON.parse(form.form_schema);
  const errors: string[] = [];

  // Validation
  // Main entity
  if (schema.mainEntityLookup && isEmptyField(submission.values.mainEntityLookup)) {
    errors.push('Required field "mainEntityLookup" is missing');
  }
  if (!schema.mainEntityLookup && schema.mainEntityMultiple && schema.mainEntityFieldMode === 'multiple') {
    schema.fields.filter((field) => field.attributeMapping.entity === 'main_entity').forEach((field) => {
      if (field.isMandatory || field.required) {
        if (isEmptyField(submission.values.mainEntityGroups)) {
          errors.push('Required field "mainEntityGroups" is missing');
        } else {
          for (let index = 0; index < submission.values.mainEntityGroups.length; index += 1) {
            const fieldValue = submission.values.mainEntityGroups[index][field.name];
            if (isEmptyField(fieldValue)) {
              errors.push(`Required field "${field.label || field.name}" is missing`);
            }
          }
        }
      }
    });
  }
  if (!schema.mainEntityLookup && schema.mainEntityMultiple && schema.mainEntityFieldMode === 'parsed') {
    if (isEmptyField(submission.values.mainEntityParsed)) {
      errors.push('Required field "mainEntityParsed" is missing');
    }
  }
  if (!schema.mainEntityLookup && !schema.mainEntityMultiple) {
    schema.fields.filter((field) => field.attributeMapping.entity === 'main_entity').forEach((field) => {
      if (field.isMandatory || field.required) {
        const fieldValue = submission.values[field.name];
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
      if (additionalEntity.lookup && isEmptyField(submission.values[`additional_${additionalEntity.id}_lookup`])) {
        errors.push(`Required field "additional_${additionalEntity.id}_lookup" is missing`);
      }
      if (!additionalEntity.lookup && additionalEntity.multiple && additionalEntity.fieldMode === 'multiple') {
        schema.fields.filter((field) => field.attributeMapping.entity === additionalEntity.id).forEach((field) => {
          if (field.isMandatory || field.required) {
            if (!submission.values[`additional_${additionalEntity.id}_groups`]) {
              errors.push(`Required field "additional_${additionalEntity.id}_groups" is missing`);
            } else {
              for (let index2 = 0; index2 < submission.values[`additional_${additionalEntity.id}_groups`].length; index2 += 1) {
                const fieldValue = submission.values[`additional_${additionalEntity.id}_groups`][index2][field.name];
                if (isEmptyField(fieldValue)) {
                  errors.push(`Required field "${field.label || field.name}" is missing`);
                }
              }
            }
          }
        });
      }
      if (!additionalEntity.lookup && additionalEntity.multiple && additionalEntity.fieldMode === 'parsed') {
        if (!submission.values[`additional_${additionalEntity.id}_parsed`]) {
          errors.push(`Required field "additional_${additionalEntity.id}_parsed" is missing`);
        }
      }
      if (!additionalEntity.lookup && !additionalEntity.multiple) {
        schema.fields.filter((field) => field.attributeMapping.entity === additionalEntity.id).forEach((field) => {
          if (field.isMandatory || field.required) {
            const fieldValue = submission.values[field.name];
            if (isEmptyField(fieldValue)) {
              errors.push(`Required field "${field.label || field.name}" is missing`);
            }
          }
        });
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
    const values = Array.isArray(submission.values.mainEntityLookup) ? submission.values.mainEntityLookup : [submission.values.mainEntityLookup];
    const mainEntities = await Promise.all(values.map((id: string) => {
      return storeLoadById<StoreEntityForm>(context, user, id, mainEntityType);
    }));
    for (let index = 0; index < mainEntities.length; index += 1) {
      mainStixEntities.push(convertStoreToStix(mainEntities[index]));
      mainEntityStixId = mainEntities[index].standard_id;
    }
  } else {
    const mainEntityFields = schema.fields.filter((field) => field.attributeMapping.entity === 'main_entity');
    if (schema.mainEntityMultiple && schema.mainEntityFieldMode === 'multiple') {
      for (let index = 0; index < submission.values.mainEntityGroups.length; index += 1) {
        let mainEntity = { entity_type: mainEntityType } as StoreEntity;
        for (let i = 0; i < mainEntityFields.length; i += 1) {
          // eslint-disable-next-line @typescript-eslint/ban-ts-comment
          // @ts-expect-error
          mainEntity[mainEntityFields[i].attributeMapping.attributeName] = submission.values.mainEntityGroups[index][mainEntityFields[i].name];
        }
        mainEntity = completeEntity(mainEntityType, mainEntity);
        mainStixEntities.push(convertStoreToStix(mainEntity));
        mainEntityStixId = mainEntity.standard_id;
      }
    } else if (schema.mainEntityMultiple && schema.mainEntityFieldMode === 'parsed') {
      for (let index = 0; index < submission.values.mainEntityParsed.length; index += 1) {
        let mainEntity = { entity_type: mainEntityType } as StoreEntity;
        if (isStixObjectAliased(mainEntityType)) {
          mainEntity.name = submission.values.mainEntityParsed[index];
        }
        if (mainEntityType === ENTITY_TYPE_MALWARE) {
          mainEntity.is_family = true;
        }
        if (mainEntityType === ENTITY_TYPE_CONTAINER_GROUPING) {
          mainEntity.context = 'form';
        }
        mainEntity = completeEntity(mainEntityType, mainEntity);
        mainStixEntities.push(convertStoreToStix(mainEntity));
        mainEntityStixId = mainEntity.standard_id;
      }
    } else {
      let mainEntity = { entity_type: mainEntityType } as StoreEntity;
      for (let i = 0; i < mainEntityFields.length; i += 1) {
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-expect-error
        mainEntity[mainEntityFields[i].attributeMapping.attributeName] = submission.values[mainEntityFields[i].name];
      }
      mainEntity = completeEntity(mainEntityType, mainEntity);
      mainStixEntities.push(convertStoreToStix(mainEntity));
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
        const values = Array.isArray(submission.values[`additional_${additionalEntity.id}_lookup`]) ? submission.values[`additional_${additionalEntity.id}_lookup`] : [submission.values[`additional_${additionalEntity.id}_lookup`]];
        const additionalEntities = await Promise.all(values.map((id: string) => {
          return storeLoadById<StoreEntityForm>(context, user, id, additionalEntityType);
        }));
        for (let index2 = 0; index2 < additionalEntities.length; index2 += 1) {
          const stixAdditionalEntity = convertStoreToStix(additionalEntities[index2]);
          bundle.objects.push(stixAdditionalEntity);
          if (additionalEntitiesMap[additionalEntity.id]) {
            additionalEntitiesMap[additionalEntity.id].push(stixAdditionalEntity.id);
          } else {
            additionalEntitiesMap[additionalEntity.id] = [stixAdditionalEntity.id];
          }
        }
      } else {
        const additionalEntityFields = schema.fields.filter((field) => field.attributeMapping.entity === additionalEntity.id);
        if (additionalEntity.multiple && additionalEntity.fieldMode === 'multiple') {
          for (let index2 = 0; index2 < submission.values[`additional_${additionalEntity.id}_groups`].length; index2 += 1) {
            let newAdditionalEntity = { entity_type: additionalEntityType } as StoreEntity;
            for (let i = 0; i < additionalEntityFields.length; i += 1) {
              // eslint-disable-next-line @typescript-eslint/ban-ts-comment
              // @ts-expect-error
              newAdditionalEntity[additionalEntityFields[i].attributeMapping.attributeName] = submission.values[`additional_${additionalEntity.id}_groups`][index2][additionalEntityFields[i].name];
            }
            newAdditionalEntity = completeEntity(additionalEntityType, newAdditionalEntity);
            const stixAdditionalEntity = convertStoreToStix(newAdditionalEntity);
            bundle.objects.push(stixAdditionalEntity);
            if (additionalEntitiesMap[additionalEntity.id]) {
              additionalEntitiesMap[additionalEntity.id].push(stixAdditionalEntity.id);
            } else {
              additionalEntitiesMap[additionalEntity.id] = [stixAdditionalEntity.id];
            }
          }
        } else if (additionalEntity.multiple && additionalEntity.fieldMode === 'parsed') {
          for (let index2 = 0; index2 < submission.values[`additional_${additionalEntity.id}_parsed`].length; index2 += 1) {
            let newAdditionalEntity = { entity_type: additionalEntityType } as StoreEntity;
            if (isStixObjectAliased(additionalEntityType)) {
              newAdditionalEntity.name = submission.values[`additional_${additionalEntity.id}_parsed`][index2];
            }
            if (mainEntityType === ENTITY_TYPE_MALWARE) {
              newAdditionalEntity.is_family = true;
            }
            if (mainEntityType === ENTITY_TYPE_CONTAINER_GROUPING) {
              newAdditionalEntity.context = 'form';
            }
            newAdditionalEntity = completeEntity(additionalEntityType, newAdditionalEntity);
            const stixAdditionalEntity = convertStoreToStix(newAdditionalEntity);
            bundle.objects.push(stixAdditionalEntity);
            if (additionalEntitiesMap[additionalEntity.id]) {
              additionalEntitiesMap[additionalEntity.id].push(stixAdditionalEntity.id);
            } else {
              additionalEntitiesMap[additionalEntity.id] = [stixAdditionalEntity.id];
            }
          }
        } else {
          let newAdditionalEntity = { entity_type: additionalEntityType } as StoreEntity;
          for (let i = 0; i < additionalEntityFields.length; i += 1) {
            // eslint-disable-next-line @typescript-eslint/ban-ts-comment
            // @ts-expect-error
            newAdditionalEntity[additionalEntityFields[i].attributeMapping.attributeName] = submission.values[additionalEntityFields[i].name];
          }
          newAdditionalEntity = completeEntity(additionalEntityType, newAdditionalEntity);
          const stixAdditionalEntity = convertStoreToStix(newAdditionalEntity);
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

  // Create relationships
  if (schema.relationships && schema.relationships.length > 0) {
    for (let i = 0; i < schema.relationships.length; i += 1) {
      const rel = schema.relationships[i];
      if (rel.fromEntity === 'main_entity') {
        for (let j = 0; j < mainStixEntities.length; j += 1) {
          for (let k = 0; k < (additionalEntitiesMap[rel.toEntity] ?? []).length; k += 1) {
            const relationshipData: Partial<StixRelation> = {
              id: `relationship--${uuidv4()}`,
              type: 'relationship',
              spec_version: '2.1',
              created: new Date().toISOString(),
              modified: new Date().toISOString(),
              relationship_type: rel.relationshipType,
              source_ref: mainStixEntities[j].id,
              target_ref: additionalEntitiesMap[rel.toEntity][k]
            };
            bundle.objects.push(relationshipData);
          }
        }
      } else if (rel.toEntity === 'main_entity') {
        for (let j = 0; j < mainStixEntities.length; j += 1) {
          for (let k = 0; k < (additionalEntitiesMap[rel.fromEntity] ?? []).length; k += 1) {
            const relationshipData: Partial<StixRelation> = {
              id: `relationship--${uuidv4()}`,
              type: 'relationship',
              spec_version: '2.1',
              created: new Date().toISOString(),
              modified: new Date().toISOString(),
              relationship_type: rel.relationshipType,
              source_ref: additionalEntitiesMap[rel.fromEntity][k],
              target_ref: mainStixEntities[j].id
            };
            bundle.objects.push(relationshipData);
          }
        }
      } else {
        for (let j = 0; j < (additionalEntitiesMap[rel.fromEntity] ?? []).length; j += 1) {
          for (let k = 0; k < (additionalEntitiesMap[rel.toEntity] ?? []).length; k += 1) {
            const relationshipData: Partial<StixRelation> = {
              id: `relationship--${uuidv4()}`,
              type: 'relationship',
              spec_version: '2.1',
              created: new Date().toISOString(),
              modified: new Date().toISOString(),
              relationship_type: rel.relationshipType,
              source_ref: additionalEntitiesMap[rel.fromEntity][j],
              target_ref: additionalEntitiesMap[rel.toEntity][k]
            };
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
    if (isDraft) {
      const draft = await addDraftWorkspace(context, user, { name: form.name });
      draftId = draft.id;
    }
    await pushToWorkerForConnector(connectorId, {
      type: 'bundle',
      applicant_id: user.id,
      content,
      work_id: work.id,
      draft_context: draftId,
      update: true
    });

    logApp.info('[FORM] Bundle sent to connector queue', { formId: form.id, workId: work.id, bundleId: bundle.id });

    return {
      success: true,
      bundleId: bundle.id,
      message: 'Form submitted successfully and sent for processing',
      entityId: mainEntityStixId
    };
  } catch (error) {
    logApp.error('[FORM] Error sending bundle to connector queue', { error });
    throw FunctionalError('Failed to process form submission', { cause: error });
  }
};
