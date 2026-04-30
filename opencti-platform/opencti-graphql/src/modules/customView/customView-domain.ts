import type { FileHandle } from 'fs/promises';
import pjson from '../../../package.json';
import { fullEntitiesList, pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import type { AuthContext, AuthUser } from '../../types/user';
import { ENTITY_TYPE_CUSTOM_VIEW, type BasicStoreEntityCustomView, type CustomViewExport, type StoreEntityCustomView } from './customView-types';
import {
  type QueryCustomViewsArgs,
  type CustomViewAddInput,
  type CustomViewDuplicateInput,
  type EditInput,
  type CustomViewImportWidgetInput,
  FilterMode,
  FilterOperator,
} from '../../generated/graphql';
import slugify from 'slug';
import {
  ENTITY_TYPE_CONTAINER_NOTE,
  ENTITY_TYPE_CONTAINER_OBSERVED_DATA,
  ENTITY_TYPE_CONTAINER_OPINION,
  ENTITY_TYPE_COURSE_OF_ACTION,
  ENTITY_TYPE_DATA_COMPONENT,
  ENTITY_TYPE_DATA_SOURCE,
} from '../../schema/stixDomainObject';
import { ENTITY_TYPE_SECURITY_COVERAGE } from '../securityCoverage/securityCoverage-types';
import { ENTITY_TYPE_CONTAINER_TASK } from '../task/task-types';
import { ENTITY_TYPE_CONTAINER_FEEDBACK } from '../case/feedback/feedback-types';
import { ABSTRACT_STIX_CORE_RELATIONSHIP, ABSTRACT_STIX_CYBER_OBSERVABLE, ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import { schemaTypesDefinition } from '../../schema/schema-types';
import { ENTITY_HASHED_OBSERVABLE_ARTIFACT } from '../../schema/stixCyberObservable';
import { addFilter } from '../../utils/filtering/filtering-utils';
import { FunctionalError } from '../../config/errors';
import { convertDashboardManifestIds, exportDashboardWidget, importDashboardWidgetConfiguration } from '../dashboard/dashboard-utils';
import { createInternalObject, deleteInternalObject, editInternalObject } from '../../domain/internalObject';
import { updateAttribute } from '../../database/middleware';
import { extractContentFrom } from '../../utils/fileToContent';
import { addCustomViewCreatedCount } from '../../manager/telemetryManager';

/**
 * Exclusion list: entity types not capable of
 * having custom views.
 */
const ENTITY_TYPES_WITHOUT_CUSTOM_VIEWS = [
  ENTITY_TYPE_CONTAINER_NOTE,
  ENTITY_TYPE_CONTAINER_OBSERVED_DATA,
  ENTITY_TYPE_CONTAINER_TASK,
  ENTITY_TYPE_CONTAINER_FEEDBACK,
  ENTITY_TYPE_CONTAINER_OPINION,
  ENTITY_TYPE_COURSE_OF_ACTION,
  ENTITY_TYPE_DATA_COMPONENT,
  ENTITY_TYPE_DATA_SOURCE,
  ENTITY_TYPE_SECURITY_COVERAGE,
];

/**
 * The cached whitelist
 */
let entityTypesCandidateToCustomViews: string[] | undefined = undefined;

const getEntityTypesCandidateToCustomViews = () => {
  if (!entityTypesCandidateToCustomViews) {
    const candidateTypes = [
      ...schemaTypesDefinition
        .get(ABSTRACT_STIX_DOMAIN_OBJECT),
      ABSTRACT_STIX_CORE_RELATIONSHIP,
      ABSTRACT_STIX_CYBER_OBSERVABLE,
      ENTITY_HASHED_OBSERVABLE_ARTIFACT,
    ];
    entityTypesCandidateToCustomViews = candidateTypes
      .filter((entityType) => !ENTITY_TYPES_WITHOUT_CUSTOM_VIEWS.includes(entityType));
  }
  return entityTypesCandidateToCustomViews;
};

const isCustomViewsAvailableForEntityType = (entityType: string) => {
  return getEntityTypesCandidateToCustomViews().includes(entityType);
};

const applyUniqueDefaultCustomViewConstraint = async (
  context: AuthContext,
  user: AuthUser,
  targetEntityType: string,
  newDefaultCustomViewId: string,
) => {
  const previousDefaultCustomViews = await fullEntitiesList<BasicStoreEntityCustomView>(
    context,
    user,
    [ENTITY_TYPE_CUSTOM_VIEW],
    {
      baseData: true,
      filters: {
        filters: [{
          key: ['target_entity_type'],
          values: [targetEntityType],
        }, {
          key: ['default'],
          values: [true],
        }, {
          key: ['id'],
          values: [newDefaultCustomViewId],
          operator: FilterOperator.NotEq,
        }],
        filterGroups: [],
        mode: FilterMode.And,
      },
    },
  );
  if (previousDefaultCustomViews.length === 0) {
    return;
  }
  // There should be only one but we never know as the constraint is not
  // enforced at the DB level.
  const promises = previousDefaultCustomViews.map((entity) => {
    return updateAttribute<StoreEntityCustomView>(
      context,
      user,
      entity.id,
      ENTITY_TYPE_CUSTOM_VIEW,
      [{
        key: 'default',
        value: [false],
      }],
    );
  });
  await Promise.all(promises);
};

const TELEMETRY = {
  customViewCreated: addCustomViewCreatedCount,
};

export const computeCustomViewPath = ({ slug, id }: BasicStoreEntityCustomView) => {
  return `${slug}-${id.replaceAll('-', '')}`;
};

export const findCustomViewById = async (
  context: AuthContext,
  user: AuthUser,
  customViewId: string,
) => {
  return storeLoadById<BasicStoreEntityCustomView>(
    context,
    user,
    customViewId,
    ENTITY_TYPE_CUSTOM_VIEW,
  );
};

export const findAllCustomViews = async (
  context: AuthContext,
  user: AuthUser,
  entityType: string | undefined | null,
  paginationOptions: Omit<QueryCustomViewsArgs, 'entityType'>,
) => {
  const entityTypeFilterGroup = addFilter(
    undefined,
    'target_entity_type',
    entityType ? [entityType] : getEntityTypesCandidateToCustomViews(),
  );
  return pageEntitiesConnection<BasicStoreEntityCustomView>(
    context,
    user,
    [ENTITY_TYPE_CUSTOM_VIEW],
    {
      ...paginationOptions,
      filters: {
        filterGroups: [
          entityTypeFilterGroup,
          ...paginationOptions.filters ? [paginationOptions.filters] : [],
        ],
        mode: FilterMode.And,
        filters: [],
      },
    },
  );
};

export const getCustomViewsSettings = (entityType: string) => {
  return { canEntityTypeHaveCustomViews: isCustomViewsAvailableForEntityType(entityType) };
};

export const addCustomView = async (
  context: AuthContext,
  user: AuthUser,
  input: CustomViewAddInput,
) => {
  if (!isCustomViewsAvailableForEntityType(input.targetEntityType)) {
    throw FunctionalError(
      'Custom views cannot be created for given entity type', {
        entityType: input.targetEntityType,
      });
  }
  const customViewToCreate = {
    description: input.description,
    manifest: input.manifest,
    name: input.name,
    target_entity_type: input.targetEntityType,
    slug: slugify(input.name),
    enabled: input.enabled ?? false,
    default: input.default ?? false,
  };
  const element = await createInternalObject<StoreEntityCustomView>(
    context,
    user,
    customViewToCreate,
    ENTITY_TYPE_CUSTOM_VIEW,
    {
      auditLogEnabled: true,
      auditLogContextSanitizer: (element) => ({
        ...element,
        manifest: '[sanitized]',
      }),
    },
  );
  TELEMETRY.customViewCreated();
  if (element.default) {
    // Unset the `default` fields for other CustomViews of the same
    // target_entity_type to enforce uniqueness constraint
    await applyUniqueDefaultCustomViewConstraint(
      context,
      user,
      element.target_entity_type,
      element.id,
    );
  }
  return element;
};

export const editCustomView = async (
  context: AuthContext,
  user: AuthUser,
  customViewId: string,
  input: EditInput[],
) => {
  const nameInput = input.find((i) => i.key === 'name');
  const defaultFieldValue = input.find((i) => i.key === 'default')?.value?.[0];
  const element = await editInternalObject<StoreEntityCustomView>(
    context,
    user,
    customViewId,
    ENTITY_TYPE_CUSTOM_VIEW,
    [
      ...input,
      ...(nameInput ? [{
        key: 'slug',
        value: [slugify(nameInput.value[0])],
      }] : []),
    ],
    {
      auditLogEnabled: true,
      auditLogContextSanitizer: (input) => input.map((entry) => ({
        ...entry,
        value: entry.key === 'manifest' ? ['[sanitized]'] : entry.value,
      })),
    },
  );
  if (defaultFieldValue) {
    // Unset the `default` fields for other CustomViews of the same
    // target_entity_type to enforce uniqueness constraint
    await applyUniqueDefaultCustomViewConstraint(
      context,
      user,
      element.target_entity_type,
      element.id,
    );
  }
  return element;
};

export const customViewImportWidgetConfiguration = async (
  context: AuthContext,
  user: AuthUser,
  customViewId: string,
  input: CustomViewImportWidgetInput,
) => {
  const { updatedManifest } = await importDashboardWidgetConfiguration(
    context,
    user,
    input.file,
    input.manifest,
  );
  return editInternalObject<StoreEntityCustomView>(
    context,
    user,
    customViewId,
    ENTITY_TYPE_CUSTOM_VIEW,
    [{ key: 'manifest', value: [updatedManifest] }],
    {
      auditLogEnabled: true,
      auditLogContextSanitizer: (input) => input.map((entry) => ({
        ...entry,
        value: entry.key === 'manifest' ? ['[sanitized]'] : entry.value,
      })),
    },
  );
};

export const exportCustomViewWidget = async (
  context: AuthContext,
  user: AuthUser,
  customView: BasicStoreEntityCustomView,
  widgetId: string,
) => {
  const result = await exportDashboardWidget(context, user, customView.manifest, widgetId);
  if (!result.success) {
    throw FunctionalError('WIDGET_EXPORT_NOT_FOUND', { customView: customView.id, widget: widgetId });
  }
  return result.data;
};

export async function duplicateCustomView(
  context: AuthContext,
  user: AuthUser,
  input: CustomViewDuplicateInput,
) {
  if (!isCustomViewsAvailableForEntityType(input.targetEntityType)) {
    throw FunctionalError(
      'Custom views cannot be created for given entity type', {
        entityType: input.targetEntityType,
      });
  }
  const customViewToCreate = {
    description: input.description,
    manifest: input.manifest,
    name: input.name,
    target_entity_type: input.targetEntityType,
    slug: slugify(input.name),
    enabled: input.enabled ?? false,
    default: input.default ?? false,
  };
  const duplicate = await createInternalObject<StoreEntityCustomView>(
    context,
    user,
    customViewToCreate,
    ENTITY_TYPE_CUSTOM_VIEW,
    {
      auditLogEnabled: true,
      auditLogContextSanitizer: (element) => ({
        ...element,
        manifest: '[sanitized]',
      }),
    },
  );
  TELEMETRY.customViewCreated();
  if (duplicate.default) {
    // Unset the `default` fields for other CustomViews of the same
    // target_entity_type to enforce uniqueness constraint
    await applyUniqueDefaultCustomViewConstraint(
      context,
      user,
      duplicate.target_entity_type,
      duplicate.id,
    );
  }
  return duplicate;
};

export const deleteCustomView = async (
  context: AuthContext,
  user: AuthUser,
  customViewId: string,
) => {
  return deleteInternalObject<StoreEntityCustomView>(
    context,
    user,
    customViewId,
    ENTITY_TYPE_CUSTOM_VIEW,
    {
      auditLogEnabled: true,
      auditLogContextSanitizer: (element) => ({
        ...element,
        manifest: '[sanitized]',
      }),
    },
  );
};

export const exportCustomView = async (
  context: AuthContext,
  user: AuthUser,
  customView: BasicStoreEntityCustomView,
) => {
  const generatedManifest = await convertDashboardManifestIds(context, user, customView.manifest ?? '', 'internal');
  const exportConfigration: CustomViewExport = {
    openCTI_version: pjson.version,
    type: 'custom-view',
    configuration: {
      name: customView.name,
      manifest: generatedManifest,
    },
  };
  return JSON.stringify(exportConfigration);
};

export const importCustomViewConfiguration = async (
  context: AuthContext,
  user: AuthUser,
  targetEntityType: string,
  file: Promise<FileHandle>,
) => {
  if (!isCustomViewsAvailableForEntityType(targetEntityType)) {
    throw FunctionalError(
      'Custom views cannot be created for given entity type', {
        entityType: targetEntityType,
      });
  }
  const parsedData: CustomViewExport = await extractContentFrom(file);
  const { manifest } = parsedData.configuration;
  // Manifest ids must be rewritten for filters
  const generatedManifest = await convertDashboardManifestIds(context, user, manifest, 'stix');
  const customViewToCreate = {
    name: parsedData.configuration.name,
    manifest: generatedManifest,
    target_entity_type: targetEntityType,
    slug: slugify(parsedData.configuration.name),
    default: false,
    enabled: false,
  };
  const imported = await createInternalObject<StoreEntityCustomView>(
    context,
    user,
    customViewToCreate,
    ENTITY_TYPE_CUSTOM_VIEW,
    {
      auditLogEnabled: true,
      auditLogContextSanitizer: (element) => ({
        ...element,
        manifest: '[sanitized]',
      }),
    },
  );
  TELEMETRY.customViewCreated();
  return imported;
};
