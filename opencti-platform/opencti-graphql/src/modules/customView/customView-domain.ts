import { pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import type { AuthContext, AuthUser } from '../../types/user';
import { ENTITY_TYPE_CUSTOM_VIEW, type BasicStoreEntityCustomView } from './customView-types';
import { type QueryCustomViewsArgs, type CustomViewAddInput } from '../../generated/graphql';
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
import { createEntity } from '../../database/middleware';
import { FunctionalError } from '../../config/errors';

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
  return await createEntity(
    context,
    user,
    customViewToCreate,
    ENTITY_TYPE_CUSTOM_VIEW,
  );
};
