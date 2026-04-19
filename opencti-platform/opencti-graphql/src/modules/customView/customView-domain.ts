import { pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import type { AuthContext, AuthUser } from '../../types/user';
import { ENTITY_TYPE_CUSTOM_VIEW, type BasicStoreEntityCustomView, type StoreEntityCustomView } from './customView-types';
import { type QueryCustomViewsArgs, type CustomViewAddInput, type CustomViewDuplicateInput, type EditInput, type CustomViewImportWidgetInput } from '../../generated/graphql';
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
import { exportDashboardWidget, importDashboardWidgetConfiguration } from '../dashboard/dashboard-utils';
import { createInternalObject, deleteInternalObject, editInternalObject } from '../../domain/internalObject';

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
  return pageEntitiesConnection<BasicStoreEntityCustomView>(
    context,
    user,
    [ENTITY_TYPE_CUSTOM_VIEW],
    {
      ...paginationOptions,
      filters: addFilter(
        undefined,
        'target_entity_type',
        entityType ? [entityType] : getEntityTypesCandidateToCustomViews(),
      ),
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
  };
  return createInternalObject<StoreEntityCustomView>(
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
};

export const editCustomView = async (
  context: AuthContext,
  user: AuthUser,
  customViewId: string,
  input: EditInput[],
) => {
  const nameInput = input.find((i) => i.key === 'name');
  return editInternalObject<StoreEntityCustomView>(
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
  };
  return createInternalObject<StoreEntityCustomView>(
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
