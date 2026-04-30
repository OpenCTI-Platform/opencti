import { v4 as uuidv4 } from 'uuid';
import Ajv from 'ajv';
import type { FileHandle } from 'fs/promises';
import { createEntity, deleteElementById, patchAttribute, updateAttribute } from '../../database/middleware';
import { fullEntitiesList, pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import type { BasicStoreEntityForm, FormSchemaDefinition, StoreEntityForm } from './form-types';
import { ENTITY_TYPE_FORM, FormSchemaDefinitionSchema } from './form-types';
import type { AuthContext, AuthUser } from '../../types/user';
import { FunctionalError } from '../../config/errors';
import { connectorIdFromIngestId, registerConnectorForIngestion, unregisterConnectorForIngestion } from '../../domain/connector';
import { publishUserAction } from '../../listener/UserActionListener';
import { logApp } from '../../config/conf';
import { pushToWorkerForConnector } from '../../database/rabbitmq';
import { createWork, updateExpectationsNumber } from '../../domain/work';
import { ConnectorPriorityGroup, ConnectorType, FilterMode, type FormSubmissionInput } from '../../generated/graphql';
import { now, nowTime } from '../../utils/format';
import { SYSTEM_USER } from '../../utils/access';
import { addDraftWorkspace } from '../draftWorkspace/draftWorkspace-domain';
import pjson from '../../../package.json';
import { extractContentFrom } from '../../utils/fileToContent';
import { addFormIntakeCreatedCount, addFormIntakeDeletedCount, addFormIntakeSubmittedCount, addFormIntakeUpdatedCount } from '../../manager/telemetryManager';
import { validateFormSubmission } from './form-validation';
import { buildMainStixEntities, buildAdditionalEntities, buildRelationships, wrapInContainerOrPush } from './form-bundle-builder';
export { completeEntity } from './form-entity-builder';

const ajv = new Ajv();
const validateSchema = ajv.compile(FormSchemaDefinitionSchema);

export const addForm = async (
  context: AuthContext,
  user: AuthUser,
  input: any,
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
    form_schema: input.form_schema,
    active: input.active ?? true,
  };

  const { element, isCreation } = await createEntity(
    context,
    user,
    formToCreate,
    ENTITY_TYPE_FORM,
    { complete: true },
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

    await addFormIntakeCreatedCount();
  }

  return element;
};

export const findById = async (
  context: AuthContext,
  user: AuthUser,
  formId: string,
): Promise<BasicStoreEntityForm> => {
  return storeLoadById<BasicStoreEntityForm>(context, user, formId, ENTITY_TYPE_FORM);
};

export const findFormPaginated = async (
  context: AuthContext,
  user: AuthUser,
  opts = {},
) => {
  return pageEntitiesConnection<BasicStoreEntityForm>(context, user, [ENTITY_TYPE_FORM], opts);
};

export const findAllForms = async (
  context: AuthContext,
  user: AuthUser,
  opts = {},
) => {
  return fullEntitiesList<BasicStoreEntityForm>(context, user, [ENTITY_TYPE_FORM], opts);
};

export const patchForm = async (
  context: AuthContext,
  user: AuthUser,
  id: string,
  patch: object,
) => {
  const patched = await patchAttribute(context, user, id, ENTITY_TYPE_FORM, patch);
  return patched.element;
};

export const formEditField = async (
  context: AuthContext,
  user: AuthUser,
  formId: string,
  input: { key: string; value: string | string[] | null }[],
): Promise<StoreEntityForm> => {
  const updates = input.map(({ key, value }) => {
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

  const { element } = await updateAttribute<StoreEntityForm>(context, user, formId, ENTITY_TYPE_FORM, updates);

  const activeUpdate = input.find(({ key }) => key === 'active');
  if (activeUpdate) {
    const isActive = activeUpdate.value === 'true' || (Array.isArray(activeUpdate.value) && activeUpdate.value[0] === 'true');
    await registerConnectorForIngestion(context, {
      id: element.id,
      type: 'FORM',
      name: element.name,
      is_running: isActive,
      connector_user_id: user.id,
    });
  }

  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates form intake \`${element.name}\``,
    context_data: { id: formId, entity_type: ENTITY_TYPE_FORM, input: { name: element.name } },
  });

  await addFormIntakeUpdatedCount();

  return element;
};

export const formDelete = async (
  context: AuthContext,
  user: AuthUser,
  formId: string,
) => {
  const form = await findById(context, user, formId);

  await unregisterConnectorForIngestion(context, formId);
  await deleteElementById(context, user, formId, ENTITY_TYPE_FORM);

  if (form) {
    await publishUserAction({
      user,
      event_type: 'mutation',
      event_scope: 'delete',
      event_access: 'administration',
      message: `deletes form intake \`${form.name}\``,
      context_data: { id: formId, entity_type: ENTITY_TYPE_FORM, input: { name: form.name } },
    });

    await addFormIntakeDeletedCount();
  }

  return formId;
};

export interface FormParsed extends Omit<StoreEntityForm, 'form_schema'> {
  form_schema: FormSchemaDefinition;
}

export const formSubmit = async (
  context: AuthContext,
  user: AuthUser,
  input: FormSubmissionInput,
  isDraft: boolean = false,
): Promise<any> => {
  const form = await findById(context, user, input.formId);
  if (!form) {
    throw FunctionalError('Form not found', { id: input.formId });
  }

  // eslint-disable-next-line no-useless-assignment
  let values = {} as Record<string, any>;
  try {
    values = JSON.parse(input.values);
  } catch (error) {
    throw FunctionalError('Cannot read values', { error });
  }

  const schema: FormSchemaDefinition = JSON.parse(form.form_schema);

  // Enforce draft settings from schema
  let finalIsDraft = isDraft;
  if (schema.isDraftByDefault === true) {
    if (schema.allowDraftOverride === false) {
      finalIsDraft = true;
    }
  }

  validateFormSubmission(schema, values);

  const bundle: any = {
    type: 'bundle',
    id: `bundle--${uuidv4()}`,
    spec_version: '2.1',
    objects: [],
  };

  const { mainEntityType } = schema;

  const { mainStixEntities, mainEntityStixId } = await buildMainStixEntities(context, user, schema, values, mainEntityType);

  const additionalEntitiesMap = await buildAdditionalEntities(context, user, schema, values, bundle);

  await buildRelationships(context, user, schema, values, mainStixEntities, additionalEntitiesMap, bundle);

  wrapInContainerOrPush(mainEntityType, mainStixEntities, bundle, schema.includeInContainer);

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
      update: true,
    });

    logApp.info('[FORM] Bundle sent to connector queue', { formId: form.id, workId: work.id, bundleId: bundle.id });

    await addFormIntakeSubmittedCount();

    return {
      success: true,
      bundleId: bundle.id,
      message: 'Form submitted successfully and sent for processing',
      entityId: finalIsDraft ? draftId : mainEntityStixId,
    };
  } catch (error) {
    logApp.error('[FORM] Error sending bundle to connector queue', { error });
    throw FunctionalError('Failed to process form submission', { cause: error });
  }
};

export const generateFormExportConfiguration = async (
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
  file: Promise<FileHandle>,
) => {
  const parsedData = await extractContentFrom(file);
  if (parsedData.type !== 'form') {
    throw FunctionalError('Invalid import file type', { expected: 'form', received: parsedData.type });
  }
  const { configuration } = parsedData;
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
    context_data: { id: createdForm.id, entity_type: ENTITY_TYPE_FORM, input: formToCreate },
  });
  return createdForm;
};
