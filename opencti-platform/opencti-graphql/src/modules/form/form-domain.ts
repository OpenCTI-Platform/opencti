import { v4 as uuidv4 } from 'uuid';
import Ajv from 'ajv';
import type { FileHandle } from 'fs/promises';
import { createEntity, deleteElementById, patchAttribute, updateAttribute } from '../../database/middleware';
import { fullEntitiesList, pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import type { BasicStoreEntityForm, FormSchemaDefinition, StoreEntityForm } from './form-types';
import { ENTITY_TYPE_FORM, FormFieldType, FormSchemaDefinitionSchema } from './form-types';
import type { AuthContext, AuthUser } from '../../types/user';
import { FunctionalError } from '../../config/errors';
import { connectorIdFromIngestId, registerConnectorForIngestion, unregisterConnectorForIngestion } from '../../domain/connector';
import { publishUserAction } from '../../listener/UserActionListener';
import { logApp } from '../../config/conf';
import { pushToWorkerForConnector } from '../../database/rabbitmq';
import { createWork } from '../../domain/work';
import { ConnectorPriorityGroup, ConnectorType, FilterMode, type DraftWorkspaceAddInput, type FormSubmissionInput, type MemberAccessInput } from '../../generated/graphql';
import { now, nowTime } from '../../utils/format';
import { BYPASS, isUserHasCapability, SYSTEM_USER } from '../../utils/access';
import { addDraftWorkspace } from '../draftWorkspace/draftWorkspace-domain';
import { ENTITY_TYPE_DRAFT_WORKSPACE } from '../draftWorkspace/draftWorkspace-types';
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

const normalizeOptionId = (option: unknown): string | undefined => {
  if (typeof option === 'object' && option !== null) {
    const optionValue = (option as { value?: string; id?: string }).value || (option as { value?: string; id?: string }).id;
    return typeof optionValue === 'string' && optionValue.length > 0 ? optionValue : undefined;
  }
  return typeof option === 'string' && option.length > 0 ? option : undefined;
};

export const resolveMainEntityAuthorFromValues = (
  schema: FormSchemaDefinition,
  values: Record<string, any>,
): string | null => {
  const createdByField = schema.fields.find((f) => f.type === FormFieldType.CreatedBy);
  const createdByKeys = Array.from(new Set([
    createdByField?.name,
    createdByField?.attributeMapping?.attributeName,
    'createdBy',
  ].filter((k): k is string => typeof k === 'string' && k.length > 0)));
  const resolveIn = (container: any): string | undefined => {
    for (let i = 0; i < createdByKeys.length; i += 1) {
      const id = normalizeOptionId(container?.[createdByKeys[i]]);
      if (id) return id;
    }
    return undefined;
  };
  return (
    resolveIn(values)
    || resolveIn(values.mainEntityFields)
    || resolveIn(Array.isArray(values.mainEntityGroups) ? values.mainEntityGroups[0] : undefined)
    || null
  );
};

export const resolveDraftFieldDefaults = (
  formName: string,
  values: Record<string, unknown>,
  draftDefaults: FormSchemaDefinition['draftDefaults'] | undefined,
  isBypass: boolean = false,
) => {
  const explicitDraftName = typeof values.draftName === 'string' ? values.draftName.trim() : '';
  const draftNameDefaultValue = (draftDefaults?.name?.defaultValue ?? '').trim();
  const defaultDraftName = draftNameDefaultValue.length > 0 ? draftNameDefaultValue : '';
  const canOverrideDraftName = isBypass || (draftDefaults?.name?.isEditable !== false);
  const finalDraftName = (canOverrideDraftName ? explicitDraftName : '') || defaultDraftName || `${formName} - ${nowTime()}`;

  const hasExplicitDraftDescription = Object.hasOwn(values, 'draftDescription');
  const explicitDraftDescription = typeof values.draftDescription === 'string' ? values.draftDescription.trim() : '';
  const draftDescriptionDefaultValue = (draftDefaults?.description?.defaultValue ?? '').trim();
  const defaultDraftDescription = draftDescriptionDefaultValue.length > 0 ? draftDescriptionDefaultValue : '';
  const canOverrideDraftDescription = isBypass || (draftDefaults?.description?.isEditable !== false);
  const finalDraftDescription = (canOverrideDraftDescription && hasExplicitDraftDescription) ? explicitDraftDescription : defaultDraftDescription;

  const hasExplicitDraftAssignees = Object.hasOwn(values, 'draftObjectAssignee');
  const explicitDraftAssignees = Array.isArray(values.draftObjectAssignee)
    ? values.draftObjectAssignee.map(normalizeOptionId).filter((id): id is string => !!id)
    : [];
  const draftAssigneeDefaults = (draftDefaults?.objectAssignee?.defaults ?? [])
    .map(normalizeOptionId)
    .filter((id): id is string => !!id);
  const defaultDraftAssignees = draftAssigneeDefaults.length > 0 ? draftAssigneeDefaults : [];
  const canOverrideDraftAssignees = isBypass || (draftDefaults?.objectAssignee?.isEditable !== false);
  const finalDraftAssignees = (canOverrideDraftAssignees && hasExplicitDraftAssignees) ? explicitDraftAssignees : defaultDraftAssignees;

  const hasExplicitDraftParticipants = Object.hasOwn(values, 'draftObjectParticipant');
  const explicitDraftParticipants = Array.isArray(values.draftObjectParticipant)
    ? values.draftObjectParticipant.map(normalizeOptionId).filter((id): id is string => !!id)
    : [];
  const draftParticipantDefaults = (draftDefaults?.objectParticipant?.defaults ?? [])
    .map(normalizeOptionId)
    .filter((id): id is string => !!id);
  const defaultDraftParticipants = draftParticipantDefaults.length > 0 ? draftParticipantDefaults : [];
  const canOverrideDraftParticipants = isBypass || (draftDefaults?.objectParticipant?.isEditable !== false);
  const finalDraftParticipants = (canOverrideDraftParticipants && hasExplicitDraftParticipants) ? explicitDraftParticipants : defaultDraftParticipants;

  return {
    finalDraftName,
    finalDraftDescription,
    finalDraftAssignees,
    finalDraftParticipants,
  };
};

const normalizeGroupsRestrictionIds = (groupsRestriction: unknown): string[] | undefined => {
  if (!Array.isArray(groupsRestriction)) {
    return undefined;
  }
  const ids = groupsRestriction
    .map((group) => normalizeOptionId(group))
    .filter((groupId): groupId is string => !!groupId);
  return ids.length > 0 ? ids : undefined;
};

type NormalizedDraftAuthorizedMemberRule = {
  value: string;
  accessRight: string;
  groupsRestrictionIds?: string[];
};

const normalizeDraftAuthorizedMemberRule = (rule: unknown): NormalizedDraftAuthorizedMemberRule | null => {
  if (rule === null || rule === undefined) {
    return null;
  }

  if (typeof rule === 'object') {
    const legacyRule = rule as { type?: string; intersectionGroup?: string };
    if (legacyRule.type === 'CREATOR') {
      return { value: 'CREATORS', accessRight: 'admin' };
    }
    if (legacyRule.type === 'AUTHOR_ORG') {
      return {
        value: 'AUTHOR',
        accessRight: 'admin',
        groupsRestrictionIds: legacyRule.intersectionGroup ? [legacyRule.intersectionGroup] : undefined,
      };
    }
  }

  const value = normalizeOptionId(rule);
  if (!value) {
    return null;
  }

  const accessRight = (typeof rule === 'object' && (rule as { accessRight?: string }).accessRight)
    ? (rule as { accessRight: string }).accessRight
    : 'admin';

  return {
    value,
    accessRight,
    groupsRestrictionIds: typeof rule === 'object'
      ? normalizeGroupsRestrictionIds((rule as { groupsRestriction?: unknown }).groupsRestriction)
      : undefined,
  };
};

const makeCompositeKey = (id: string, groupsRestrictionIds: string[] | undefined): string => {
  if (!groupsRestrictionIds || groupsRestrictionIds.length === 0) return id;
  return `${id}::${[...groupsRestrictionIds].sort().join(',')}`;
};

export const resolveAuthorizedMembersForDraft = (
  user: AuthUser,
  rawRules: unknown[],
  createdBy: string | null = null,
): MemberAccessInput[] => {
  const authorizedMembersMap = new Map<string, MemberAccessInput>();
  rawRules.forEach((rule) => {
    const normalizedRule = normalizeDraftAuthorizedMemberRule(rule);
    if (!normalizedRule) {
      return;
    }

    const { value, accessRight, groupsRestrictionIds } = normalizedRule;
    if (value === 'CREATORS') {
      const existing = authorizedMembersMap.get(user.id)
        || { id: user.id, access_right: accessRight };

      authorizedMembersMap.set(user.id, {
        ...existing,
        access_right: existing.access_right || accessRight,
        // CREATORS is always unrestricted in form intake.
        groups_restriction_ids: undefined,
      });
      return;
    }

    if (value === 'AUTHOR') {
      if (createdBy) {
        // AUTHOR resolves to the STIX author of the draft (the createdBy entity, typically an Organization).
        const key = makeCompositeKey(createdBy, groupsRestrictionIds);
        if (!authorizedMembersMap.has(key)) {
          authorizedMembersMap.set(key, {
            id: createdBy,
            access_right: accessRight,
            groups_restriction_ids: groupsRestrictionIds,
          });
        }
      }
      return;
    }

    // Same composite-key logic for direct org/user/group rules.
    const key = makeCompositeKey(value, groupsRestrictionIds);
    if (!authorizedMembersMap.has(key)) {
      authorizedMembersMap.set(key, {
        id: value,
        access_right: accessRight,
        groups_restriction_ids: groupsRestrictionIds,
      });
    }
  });

  return Array.from(authorizedMembersMap.values());
};

// Submit a form and convert to STIX bundle
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

  const isBypass = isUserHasCapability(user, BYPASS);
  validateFormSubmission(schema, values, isBypass);
  const bundle: any = {
    type: 'bundle',
    id: `bundle--${uuidv4()}`,
    spec_version: '2.1',
    objects: [],
  };

  const { mainEntityType } = schema;

  const { mainStixEntities, mainEntityStixId } = await buildMainStixEntities(context, user, schema, values, mainEntityType, isBypass);

  const additionalEntitiesMap = await buildAdditionalEntities(context, user, schema, values, bundle, isBypass);

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

    let draftId = null;
    if (finalIsDraft) {
      let createdBy: string | null = null;
      const {
        finalDraftName,
        finalDraftDescription,
        finalDraftAssignees,
        finalDraftParticipants,
      } = resolveDraftFieldDefaults(form.name, values, schema.draftDefaults, isBypass);

      // Apply draft defaults for author
      const canOverrideDraftAuthor = isBypass || (schema.draftDefaults?.author?.isEditable !== false);
      const isAuthorRequired = schema.draftDefaults?.author?.isRequired === true;
      const hasExplicitDraftAuthor = Object.hasOwn(values, 'draftAuthor');
      if (canOverrideDraftAuthor && values.draftAuthor) {
        createdBy = normalizeOptionId(values.draftAuthor) || null;
      } else if (canOverrideDraftAuthor && hasExplicitDraftAuthor && !isAuthorRequired && schema.draftDefaults?.author?.type !== 'main_entity_author') {
        // User explicitly cleared the field; it's editable and not required → honour the opt-out
        // Exception: main_entity_author type — empty means "inherit from main entity", not opt-out
        createdBy = null;
      } else if (schema.draftDefaults?.author) {
        if (schema.draftDefaults.author.type === 'static') {
          createdBy = schema.draftDefaults.author.defaultValue || null;
        } else if (schema.draftDefaults.author.type === 'main_entity_author') {
          createdBy = resolveMainEntityAuthorFromValues(schema, values);
        } else if (schema.draftDefaults.author.type === 'none') {
          createdBy = null;
        }
      }

      // Apply explicit authorized members from form submission
      // Bypass users can always override; non-bypass users can override when the field is editable
      const canOverrideAuthorizedMembers = isBypass || schema.draftDefaults?.authorizedMembers?.isEditable;
      let authorized_members: MemberAccessInput[] = [];
      if (canOverrideAuthorizedMembers && Array.isArray(values.draftAuthorizedMembers)) {
        authorized_members = resolveAuthorizedMembersForDraft(user, values.draftAuthorizedMembers, createdBy);
      } else if (schema.draftDefaults?.authorizedMembers?.enabled && schema.draftDefaults.authorizedMembers.defaults) {
        authorized_members = resolveAuthorizedMembersForDraft(user, schema.draftDefaults.authorizedMembers.defaults, createdBy);
      }

      const draftInput: DraftWorkspaceAddInput & { bypassMandatoryAttributes?: boolean } = {
        name: finalDraftName,
      };
      if (finalDraftDescription.length > 0) draftInput.description = finalDraftDescription;
      if (finalDraftAssignees.length > 0) draftInput.objectAssignee = finalDraftAssignees;
      if (finalDraftParticipants.length > 0) draftInput.objectParticipant = finalDraftParticipants;
      if (createdBy) draftInput.createdBy = createdBy;
      if (authorized_members.length > 0) draftInput.authorized_members = authorized_members;
      // Form intake configuration must override customization mandatory attributes.
      draftInput.bypassMandatoryAttributes = true;

      const draft = await addDraftWorkspace(context, SYSTEM_USER, draftInput);
      draftId = draft.id;
      // Patch creator_id to the actual submitter since the draft was created with SYSTEM_USER
      await patchAttribute(context, SYSTEM_USER, draft.id, ENTITY_TYPE_DRAFT_WORKSPACE, { creator_id: [user.id] });
    }
    await pushToWorkerForConnector(connectorId, {
      type: 'bundle',
      applicant_id: user.id,
      content,
      work_id: work.id,
      draft_id: draftId,
      update: true,
      no_split: true,
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
