import { fullEntitiesList, storeLoadById } from '../../database/middleware-loader';
import type { AuthContext, AuthUser } from '../../types/user';
import { ENTITY_TYPE_CUSTOM_VIEW, type BasicStoreEntityCustomView } from './customView-types';
import { FilterMode } from '../../generated/graphql';
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

function isCustomViewsAvailableForEntityType(entityType: string) {
  const candidateTypes = [
    ...schemaTypesDefinition
      .get(ABSTRACT_STIX_DOMAIN_OBJECT),
    ABSTRACT_STIX_CORE_RELATIONSHIP,
    ABSTRACT_STIX_CYBER_OBSERVABLE,
    ENTITY_HASHED_OBSERVABLE_ARTIFACT,
  ];
  return candidateTypes.includes(entityType)
    && !ENTITY_TYPES_WITHOUT_CUSTOM_VIEWS.includes(entityType);
}

export function computeCustomViewPath({ slug, id }: BasicStoreEntityCustomView) {
  return `${slug}-${id.replaceAll('-', '')}`;
}

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

export const getCustomViewsDisplayContext = async (context: AuthContext, user: AuthUser) => {
  const allCustomViewEntities = await fullEntitiesList<BasicStoreEntityCustomView>(
    context,
    user,
    [ENTITY_TYPE_CUSTOM_VIEW],
  );
  const customViewInfoMap = allCustomViewEntities.reduce((infoMap, customViewEntity) => {
    const infos = infoMap.get(customViewEntity.target_entity_type) ?? [];
    infos.push(customViewEntity);
    infoMap.set(customViewEntity.target_entity_type, infos);
    return infoMap;
  }, new Map<string, BasicStoreEntityCustomView[]>());
  return Array.from(customViewInfoMap.keys()).reduce((acc, targetEntityType) => {
    if (!isCustomViewsAvailableForEntityType(targetEntityType)) {
      return acc;
    }
    const customViewsInfos = customViewInfoMap.get(targetEntityType) ?? [];
    acc.push({
      entityType: targetEntityType,
      customViews: customViewsInfos,
    });
    return acc;
  }, [] as {
    customViews: BasicStoreEntityCustomView[];
    entityType: string;
  }[]);
};

// Settings Use Cases (admin users)

export const getCustomViewsSettings = async (
  context: AuthContext,
  user: AuthUser,
  entityType: string,
) => {
  if (!isCustomViewsAvailableForEntityType(entityType)) {
    return {
      canEntityTypeHaveCustomViews: false,
      customViews: [],
    };
  }
  const customViewEntities = await fullEntitiesList<BasicStoreEntityCustomView>(
    context,
    user,
    [ENTITY_TYPE_CUSTOM_VIEW],
    {
      filters: {
        filters: [{
          key: ['target_entity_type'],
          values: [entityType],
        }],
        filterGroups: [],
        mode: FilterMode.And,
      },
    },
  );
  return {
    canEntityTypeHaveCustomViews: true,
    customViews: customViewEntities,
  };
};
