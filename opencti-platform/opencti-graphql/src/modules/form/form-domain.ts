import { v4 as uuidv4 } from 'uuid';
import Ajv from 'ajv';
import { FilterMode } from '../../generated/graphql';
import { createEntity, deleteElementById, updateAttribute } from '../../database/middleware';
import { pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import type { BasicStoreEntityForm, StoreEntityForm, FormSchemaDefinition, FormSubmissionData } from './form-types';
import { ENTITY_TYPE_FORM, FormSchemaDefinitionSchema } from './form-types';
import type { AuthContext, AuthUser } from '../../types/user';
import type { StixBundle, StixObject } from '../../types/stix-2-1-common';
import { FunctionalError } from '../../config/errors';
import { convertStoreToStix } from '../../database/stix-2-1-converter';
import { generateStandardId } from '../../schema/identifier';
import { pushToConnector } from '../../database/rabbitmq';

const ajv = new Ajv();
const validateSchema = ajv.compile(FormSchemaDefinitionSchema);

// STIX spec version
const STIX_SPEC_VERSION = '2.1';

// Container entity types (from backend constants)
const CONTAINER_TYPES = [
  'Case-Incident',
  'Case-Rfi',
  'Case-Rft',
  'Feedback',
  'Task',
  'Note',
  'Observed-Data',
  'Opinion',
  'Report',
  'Grouping',
];

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
    form_schema: input.form_schema, // Store as JSON string
    active: input.active ?? true,
  };

  return createEntity(context, user, formToCreate, ENTITY_TYPE_FORM) as Promise<BasicStoreEntityForm>;
};

export const findById = async (
  context: AuthContext,
  user: AuthUser,
  formId: string
): Promise<StoreEntityForm | null> => {
  return storeLoadById<StoreEntityForm>(context, user, formId, ENTITY_TYPE_FORM);
};

export const findAll = async (
  context: AuthContext,
  user: AuthUser,
  args: any
): Promise<any> => {
  const filters = args.filters || { mode: FilterMode.And, filters: [], filterGroups: [] };
  return pageEntitiesConnection(context, user, [ENTITY_TYPE_FORM], { ...args, filters });
};

export const formEdit = async (
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

  const result = await updateAttribute(context, user, formId, ENTITY_TYPE_FORM, updates);
  return result as StoreEntityForm;
};

export const formDelete = async (
  context: AuthContext,
  user: AuthUser,
  formId: string
): Promise<boolean> => {
  await deleteElementById(context, user, formId, ENTITY_TYPE_FORM);
  return true;
};

export interface FormParsed extends Omit<StoreEntityForm, 'form_schema'> {
  form_schema: FormSchemaDefinition;
}

export const parseFormSchema = (form: StoreEntityForm): FormParsed => {
  let form_schema: FormSchemaDefinition;
  try {
    form_schema = JSON.parse(form.form_schema);
  } catch (error) {
    throw FunctionalError(`Invalid JSON in form schema: ${error}`);
  }

  return {
    ...form,
    form_schema,
  };
};

// Build a STIX domain object
function buildStixDomainObject(entityType: string, data: any): StixObject {
  const id = generateStandardId(entityType, data);

  // Build base STIX object
  const stixObject: any = {
    type: entityType.toLowerCase().replace(/_/g, '-'),
    spec_version: STIX_SPEC_VERSION,
    id: id as any, // Cast to any to bypass strict type checking
    created: new Date().toISOString(),
    modified: new Date().toISOString(),
    ...data,
  };

  return stixObject;
}

// Build a STIX relationship
function buildStixRelationship(sourceRef: string, targetRef: string, relationshipType: string): StixObject {
  const id = generateStandardId('relationship', {
    source_ref: sourceRef,
    target_ref: targetRef,
    relationship_type: relationshipType,
  });

  const stixRelationship: any = {
    type: 'relationship',
    spec_version: STIX_SPEC_VERSION,
    id: id as any, // Cast to any to bypass strict type checking
    created: new Date().toISOString(),
    modified: new Date().toISOString(),
    relationship_type: relationshipType,
    source_ref: sourceRef,
    target_ref: targetRef,
    extensions: {},
  };

  return stixRelationship;
}

// Build the main STIX entity from form schema and submission
function buildMainStixEntity(schema: FormSchemaDefinition, submission: FormSubmissionData): StixObject {
  const entityData: any = {
    confidence: submission.confidence,
  };

  // Map form fields to STIX properties (only simple fields without relationships)
  schema.fields.forEach((field) => {
    if (field.stixPath && submission.values[field.id] !== undefined && !field.relationship) {
      // Parse the STIX path (e.g., "name" or "external_references[0].source_name")
      const path = field.stixPath.split(/[.[\]]+/).filter(Boolean);
      let current = entityData;
      path.slice(0, -1).forEach((segment) => {
        if (!current[segment]) {
          current[segment] = {};
        }
        current = current[segment];
      });
      current[path[path.length - 1]] = submission.values[field.id];
    }
  });

  // Apply markings from schema if defined
  if (schema.markings) {
    entityData.object_marking_refs = schema.markings;
  }

  // Apply confidence
  if (schema.confidence) {
    entityData.confidence = schema.confidence;
  }

  // Apply createdByRef
  if (schema.createdByRef) {
    entityData.created_by_ref = schema.createdByRef;
  }

  return buildStixDomainObject(schema.mainEntityType, entityData);
}

// Process field with entity creation/lookup and relationships
async function processFieldToStix(
  context: AuthContext,
  user: AuthUser,
  field: any,
  value: any,
  mainEntityRef: string,
  allFields: any[],
  allValues: any,
  createdEntities: Map<string, string> // Map field ID to entity ID
): Promise<{ entities: StixObject[]; relationships: StixObject[] }> {
  const entities: StixObject[] = [];
  const relationships: StixObject[] = [];

  if (!value || !field.stixType) {
    return { entities, relationships };
  }

  const values = Array.isArray(value) ? value : [value];
  const entityIds: string[] = [];

  // Handle entity creation from text
  if ((field.type === 'text' || field.type === 'textarea') && field.stixType) {
    values.filter((val) => typeof val === 'string').forEach((val) => {
      // Parse based on parseMode
      let entityNames: string[] = [];

      if (field.parseMode === 'line') {
        // Split by newlines
        entityNames = val.split(/\r?\n/).map((s: string) => s.trim()).filter(Boolean);
      } else {
        // Default to comma separation
        entityNames = val.split(',').map((s: string) => s.trim()).filter(Boolean);
      }

      entityNames.forEach((name) => {
        // Build the STIX entity
        const entity = buildStixDomainObject(field.stixType, { name });
        entities.push(entity);
        entityIds.push(entity.id);
      });
    });
  }

  // Handle entity lookup by ID
  if (field.type === 'entity-lookup' || field.type === 'select' || field.type === 'multiselect') {
    // Fetch all selected entities
    const entityPromises = values.map(async (entityId) => {
      try {
        const entity = await storeLoadById(context, user, entityId, field.stixType);
        return entity;
      } catch {
        return null; // Entity not found, skip it
      }
    });

    const loadedEntities = (await Promise.all(entityPromises)).filter(Boolean);

    loadedEntities.forEach((entity) => {
      if (entity) {
        // Convert to STIX
        const stixEntity = convertStoreToStix(entity as any);
        entities.push(stixEntity);
        entityIds.push(stixEntity.id);
      }
    });
  }

  // Store created entity IDs for field-to-field relationships
  if (entityIds.length > 0) {
    createdEntities.set(field.id, entityIds[0]); // Store first entity ID for simplicity
  }

  // Create relationships if configured
  if (field.relationship && entityIds.length > 0) {
    const { type: relType, target, direction = 'from' } = field.relationship;

    if (relType && target) {
      entityIds.forEach((entityId) => {
        let targetRef = '';

        if (target === 'main_entity') {
          targetRef = mainEntityRef;
        } else {
          // Field-to-field relationship
          targetRef = createdEntities.get(target) || '';
        }

        if (targetRef) {
          const relationship = buildStixRelationship(
            direction === 'from' ? entityId : targetRef,
            direction === 'from' ? targetRef : entityId,
            relType
          );
          relationships.push(relationship);
        }
      });
    }
  }

  return { entities, relationships };
}

// Submit a form and convert to STIX bundle
export const submitForm = async (
  context: AuthContext,
  user: AuthUser,
  submission: FormSubmissionData
): Promise<StixBundle> => {
  // Load the form
  const form = await findById(context, user, submission.formId);
  if (!form) {
    throw FunctionalError('Form not found');
  }

  const parsedForm = parseFormSchema(form);
  const { form_schema } = parsedForm;

  // Validate required fields
  form_schema.fields.forEach((field) => {
    if (field.required && !submission.values[field.id]) {
      throw FunctionalError(`Required field ${field.name} is missing`);
    }
  });

  // Build the main STIX entity
  const mainEntity = buildMainStixEntity(form_schema, submission);
  const stixObjects: StixObject[] = [mainEntity];

  // Check if main entity is a container
  const isContainer = (form_schema as any).isContainer || CONTAINER_TYPES.includes(form_schema.mainEntityType);
  const containerRef = isContainer ? mainEntity.id : null;

  // Track created entities for field-to-field relationships
  const createdEntities = new Map<string, string>();

  // Process fields in order to handle field-to-field dependencies
  const fieldProcessingPromises = form_schema.fields
    .filter((field) => submission.values[field.id])
    .map((field) => processFieldToStix(
      context,
      user,
      field,
      submission.values[field.id],
      mainEntity.id,
      form_schema.fields,
      submission.values,
      createdEntities
    ));

  const fieldResults = await Promise.all(fieldProcessingPromises);

  // Collect all entities and relationships
  const allEntities: StixObject[] = [];
  const allRelationships: StixObject[] = [];

  fieldResults.forEach((result) => {
    allEntities.push(...result.entities);
    allRelationships.push(...result.relationships);
  });

  // If main entity is a container, create object-refs relationships
  if (containerRef && allEntities.length > 0) {
    // Add all entities as object_refs
    (mainEntity as any).object_refs = allEntities.map((e) => e.id);
  }

  // Add all objects to the bundle
  stixObjects.push(...allEntities, ...allRelationships);

  // Create STIX bundle
  const bundle: StixBundle = {
    type: 'bundle',
    spec_version: STIX_SPEC_VERSION,
    id: `bundle--${uuidv4()}`,
    objects: stixObjects,
  };

  // Push the bundle to a connector for processing
  // Using a generic internal connector ID for form submissions
  const connectorId = 'form-submission-processor';
  const message = {
    type: 'bundle',
    bundle,
    context: {
      formId: submission.formId,
      formName: form.name,
      userId: user.id,
      submissionId: uuidv4(),
    },
  };

  await pushToConnector(connectorId, message);

  // Return the bundle
  return bundle;
};
