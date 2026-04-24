import { fullEntitiesList, pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import type { AuthContext, AuthUser } from '../../types/user';
import { ENTITY_TYPE_CUSTOM_VIEW, type BasicStoreEntityCustomView, type StoreEntityCustomView } from './customView-types';
import {
  FilterMode,
  FilterOperator,
  type QueryCustomViewsArgs,
  type CustomViewAddInput,
  type CustomViewDuplicateInput,
  type EditInput,
  type ImportWidgetInput,
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
import { createEntity, updateAttribute, deleteElementById } from '../../database/middleware';
import { now } from '../../utils/format';
import { FunctionalError } from '../../config/errors';
import { publishUserAction } from '../../listener/UserActionListener';
import { notify } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { exportWidget, processImportWidgetConfiguration, sanitizeElementForPublishAction } from '../workspace/workspace-domain';
import { Promise } from 'bluebird';

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

// View Use Cases (all authed users)

export const getCustomViewByIdForDisplay = async (
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
  await new Promise((resolve) => setTimeout(() => {
    resolve();
  }, 10_000));
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

// Settings Use Cases (admin users)

export const getCustomViewById = async (context: AuthContext, user: AuthUser, customViewId: string) => {
  return storeLoadById<BasicStoreEntityCustomView>(
    context,
    user,
    customViewId,
    ENTITY_TYPE_CUSTOM_VIEW,
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
  const created_at = now();
  const customViewToCreate = {
    description: input.description,
    manifest: input.manifest,
    name: input.name,
    target_entity_type: input.targetEntityType,
    slug: slugify(input.name),
    created_at,
    updated_at: created_at,
  };
  return await createEntity(
    context,
    user,
    customViewToCreate,
    ENTITY_TYPE_CUSTOM_VIEW,
  );
};

export const editCustomView = async (
  context: AuthContext,
  user: AuthUser,
  customViewId: string,
  input: EditInput[],
) => {
  const nameInput = input.find((i) => i.key === 'name');
  const defaultFieldValue = input.find((i) => i.key === 'default')?.value?.[0];
  const { element } = await updateAttribute<StoreEntityCustomView>(
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
  );
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates \`${input.map((i) => i.key).join(', ')}\` for custom view ${element.name}`,
    context_data: { id: element.id, entity_type: ENTITY_TYPE_CUSTOM_VIEW, input },
  });
  await notify(BUS_TOPICS[ENTITY_TYPE_CUSTOM_VIEW].EDIT_TOPIC, element, user);
  // Unset the `default` fields for other CustomViews of the same
  // target_entity_type to enforce uniqueness constraint
  if (typeof defaultFieldValue === 'boolean' && defaultFieldValue) {
    const previousDefaultCustomViews = await fullEntitiesList<BasicStoreEntityCustomView>(
      context,
      user,
      [ENTITY_TYPE_CUSTOM_VIEW],
      {
        filters: {
          filters: [{
            key: ['target_entity_type'],
            values: [element.target_entity_type],
          }, {
            key: ['default'],
            values: [true],
          }, {
            key: ['id'],
            values: [element.id],
            operator: FilterOperator.NotEq,
          }],
          filterGroups: [],
          mode: FilterMode.And,
        },
      },
    );
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
  }
  return element;
};

export const customViewImportWidgetConfiguration = async (
  context: AuthContext,
  user: AuthUser,
  customViewId: string,
  input: ImportWidgetInput,
) => {
  const { updatedManifest, importedWidgetId } = await processImportWidgetConfiguration(
    context,
    user,
    input,
  );
  const { element } = await updateAttribute<StoreEntityCustomView>(
    context,
    user,
    customViewId,
    ENTITY_TYPE_CUSTOM_VIEW,
    [{ key: 'manifest', value: [updatedManifest] }],
  );

  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: 'extended',
    message: `import widget (id : ${importedWidgetId}) in custom view (id : ${customViewId})`,
    context_data: {
      id: customViewId,
      entity_type: ENTITY_TYPE_CUSTOM_VIEW,
      input: sanitizeElementForPublishAction(element),
    },
  });
  await notify(BUS_TOPICS[ENTITY_TYPE_CUSTOM_VIEW].EDIT_TOPIC, element, user);
  return element;
};

export const exportCustomViewWidget = (
  auth: AuthContext,
  user: AuthUser,
  customView: BasicStoreEntityCustomView,
  widgetId: string,
) => {
  return exportWidget(auth, user, customView, widgetId);
};

export async function duplicateCustomView(
  context: AuthContext,
  user: AuthUser,
  input: CustomViewDuplicateInput,
) {
  const created_at = now();
  const customViewToCreate = {
    ...input,
    slug: slugify(input.name),
    created_at,
    updated_at: created_at,
    enabled: false,
    default: false,
  };
  const entity = await createEntity(
    context,
    user,
    customViewToCreate,
    ENTITY_TYPE_CUSTOM_VIEW,
  );
  const sanitizeElement = { ...input, manifest: undefined };
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: 'extended',
    message: `creates custom view \`${entity.name}\` from custom-named duplication`,
    context_data: { id: entity.id, entity_type: ENTITY_TYPE_CUSTOM_VIEW, input: sanitizeElement },
  });
  await notify(BUS_TOPICS[ENTITY_TYPE_CUSTOM_VIEW].ADDED_TOPIC, entity, user);
  return entity;
};

export const deleteCustomView = async (
  context: AuthContext,
  user: AuthUser,
  customViewId: string,
) => {
  await deleteElementById(
    context,
    user,
    customViewId,
    ENTITY_TYPE_CUSTOM_VIEW,
  );

  return customViewId;
};
