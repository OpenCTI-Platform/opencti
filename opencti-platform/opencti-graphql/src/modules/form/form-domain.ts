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
import { ENTITY_TYPE_IDENTITY, OPENCTI_SYSTEM_UUID } from '../../schema/general';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../../schema/stixMetaObject';

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

// Submit a form and convert to STIX bundle
export const submitForm = async (
  context: AuthContext,
  user: AuthUser,
  submission: FormSubmissionData,
  isDraft: boolean = false
): Promise<any> => {
  // Load the form
  const form = await findById(context, user, submission.formId);
  if (!form) {
    throw FunctionalError('Form not found');
  }

  // Parse the schema
  const schema: FormSchemaDefinition = JSON.parse(form.form_schema);

  // Simple validation - check required fields based on schema
  const errors: string[] = [];

  // Check if we need to look for mandatory fields by their attribute name instead
  const nameField = schema.fields.find((f) => f.attributeMapping?.attributeName === 'name' && (f.isMandatory || f.required));
  if (nameField) {
    const nameValue = submission.values[nameField.name] || submission.values.name;
    if (!nameValue || nameValue === '') {
      errors.push('Required field "name" is missing');
    }
  }

  schema.fields.forEach((field) => {
    if (field.isMandatory || field.required) {
      const fieldValue = submission.values[field.name];
      if (fieldValue === undefined || fieldValue === null || fieldValue === '') {
        // Skip if this is the name field we already checked
        if (field.attributeMapping?.attributeName !== 'name') {
          errors.push(`Required field "${field.label || field.name}" is missing`);
        }
      }
    }
  });

  if (errors.length > 0) {
    throw FunctionalError(errors.join(', '));
  }

  // Get STIX ID from submission or generate one
  const mainEntityStixId = submission.values.x_opencti_stix_ids?.[0]
    || generateStandardId(schema.mainEntityType || 'report', {});

  // Create the bundle structure
  const bundle: any = {
    type: 'bundle',
    id: `bundle--${uuidv4()}`,
    spec_version: '2.1',
    objects: []
  };

  // Create main entity
  const mainEntityType = schema.mainEntityType || 'Report';
  const mainEntity: any = {
    id: mainEntityStixId,
    type: mainEntityType.toLowerCase().replace(/_/g, '-'),
    spec_version: '2.1',
    created: new Date().toISOString(),
    modified: new Date().toISOString(),
    x_opencti_is_inferred: isDraft // Mark entity as draft if requested
  };

  // Map fields to main entity based on schema
  const mainEntityFields = schema.fields.filter((field) => field.attributeMapping.entity === 'main_entity');
  await Promise.all(mainEntityFields.map(async (field) => {
    const value = submission.values[field.name];
    if (value !== undefined && value !== null && value !== '') {
      // Map to the correct STIX property with special handling for reference fields
      const stixProperty = field.attributeMapping.attributeName || field.name;

      // Special handling for reference fields based on field type
      if (field.type === 'objectMarking') {
        // Frontend sends array of internal IDs, need to resolve to standard_ids
        const markingIds = Array.isArray(value) ? value : [value];
        const markings = await Promise.all(
          markingIds.filter((id: any) => id).map(async (id: string) => {
            // If it's already a standard_id format, use it directly
            if (id.startsWith('marking-definition--')) {
              return id;
            }
            // Otherwise resolve internal ID to standard_id
            const marking = await storeLoadById(context, user, id, ENTITY_TYPE_MARKING_DEFINITION);
            return marking ? marking.standard_id : null;
          })
        );
        mainEntity.object_marking_refs = markings.filter((id: any) => id !== null);
      } else if (field.type === 'createdBy') {
        // Frontend sends internal ID, need to resolve to standard_id
        if (value) {
          // If it's already a standard_id format, use it directly
          if (typeof value === 'string' && value.includes('--')) {
            mainEntity.created_by_ref = value;
          } else {
            // Resolve internal ID to standard_id
            const identity = await storeLoadById(context, user, value, ENTITY_TYPE_IDENTITY);
            if (identity) {
              mainEntity.created_by_ref = identity.standard_id;
            }
          }
        }
      } else if (field.type === 'objectLabel') {
        // Frontend sends array of label value strings (not IDs)
        mainEntity.labels = Array.isArray(value) ? value : [value];
      } else {
        // Default mapping for other fields
        mainEntity[stixProperty] = value;
      }
    }
  }));

  // Main entity ID is already set above
  bundle.objects.push(mainEntity);

  // Process additional entities if any
  const additionalEntityIds: Record<string, string> = {};
  if (schema.additionalEntities && schema.additionalEntities.length > 0) {
    await Promise.all(schema.additionalEntities.map(async (additionalEntity) => {
      const entityType = additionalEntity.entityType || 'Threat-Actor';
      const entity: any = {
        type: entityType.toLowerCase().replace(/_/g, '-'),
        spec_version: '2.1',
        created: new Date().toISOString(),
        modified: new Date().toISOString()
      };

      // Map fields for this additional entity
      const entityFields = schema.fields.filter((field) => field.attributeMapping.entity === additionalEntity.id);
      await Promise.all(entityFields.map(async (field) => {
        const value = submission.values[field.name];
        if (value !== undefined && value !== null && value !== '') {
          const stixProperty = field.attributeMapping.attributeName || field.name;

          // Special handling for reference fields based on field type
          if (field.type === 'objectMarking') {
            // Frontend sends array of internal IDs, need to resolve to standard_ids
            const markingIds = Array.isArray(value) ? value : [value];
            const markings = await Promise.all(
              markingIds.filter((id: any) => id).map(async (id: string) => {
                // If it's already a standard_id format, use it directly
                if (id.startsWith('marking-definition--')) {
                  return id;
                }
                // Otherwise resolve internal ID to standard_id
                const marking = await storeLoadById(context, user, id, ENTITY_TYPE_MARKING_DEFINITION);
                return marking ? marking.standard_id : null;
              })
            );
            entity.object_marking_refs = markings.filter((id: any) => id !== null);
          } else if (field.type === 'createdBy') {
            // Frontend sends internal ID, need to resolve to standard_id
            if (value) {
              // If it's already a standard_id format, use it directly
              if (typeof value === 'string' && value.includes('--')) {
                entity.created_by_ref = value;
              } else {
                // Resolve internal ID to standard_id
                const identity = await storeLoadById(context, user, value, ENTITY_TYPE_IDENTITY);
                if (identity) {
                  entity.created_by_ref = identity.standard_id;
                }
              }
            }
          } else if (field.type === 'objectLabel') {
            // Frontend sends array of label value strings (not IDs)
            entity.labels = Array.isArray(value) ? value : [value];
          } else {
            // Default mapping for other fields
            entity[stixProperty] = value;
          }
        }
      }));

      // Generate proper STIX ID for additional entity
      const entityId = generateStandardId(entityType, entity);
      entity.id = entityId;
      additionalEntityIds[additionalEntity.id] = entityId;
      bundle.objects.push(entity);

      // If main entity is a container, create relationship
      if (schema.isContainer && mainEntity.type.includes('report')) {
        const relationshipData: any = {
          type: 'relationship',
          spec_version: '2.1',
          created: new Date().toISOString(),
          modified: new Date().toISOString(),
          relationship_type: 'object',
          source_ref: mainEntityStixId,
          target_ref: entityId
        };
        const relationshipId = generateStandardId('stix-core-relationship', relationshipData);
        relationshipData.id = relationshipId;
        bundle.objects.push(relationshipData);
      }
    }));
  }

  // Process explicit relationships if any
  if (schema.relationships && schema.relationships.length > 0) {
    schema.relationships.forEach((rel) => {
      const sourceRef = rel.fromEntity === 'main_entity' ? mainEntityStixId : additionalEntityIds[rel.fromEntity];
      const targetRef = rel.toEntity === 'main_entity' ? mainEntityStixId : additionalEntityIds[rel.toEntity];

      if (sourceRef && targetRef) {
        const relationshipData: any = {
          type: 'relationship',
          spec_version: '2.1',
          created: new Date().toISOString(),
          modified: new Date().toISOString(),
          relationship_type: rel.relationshipType,
          source_ref: sourceRef,
          target_ref: targetRef
        };
        const relationshipId = generateStandardId('stix-core-relationship', relationshipData);
        relationshipData.id = relationshipId;
        bundle.objects.push(relationshipData);
      }
    });
  }

  // Log the full STIX bundle before sending
  logApp.info('[FORM] STIX Bundle generated', { bundleId: bundle.id, objectCount: bundle.objects.length, bundle });

  try {
    // Send the bundle to the connector queue for ingestion
    const connectorId = connectorIdFromIngestId(form.id);
    const connector = { internal_id: connectorId, connector_type: ConnectorType.ExternalImport };
    const workName = `Form submission @ ${now()}`;
    const work: any = await createWork(context, SYSTEM_USER, connector, workName, connector.internal_id, { receivedTime: now() });

    const stixBundle = JSON.stringify(bundle);
    const content = Buffer.from(stixBundle, 'utf-8').toString('base64');

    if (bundle.objects.length === 1) {
      // Only add explicit expectation if the worker will not split anything
      await updateExpectationsNumber(context, SYSTEM_USER, work.id, bundle.objects.length);
    }

    await pushToWorkerForConnector(connectorId, {
      type: 'bundle',
      applicant_id: user.id ?? OPENCTI_SYSTEM_UUID,
      content,
      work_id: work.id,
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
