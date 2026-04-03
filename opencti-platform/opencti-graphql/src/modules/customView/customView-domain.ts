import { fullEntitiesList, storeLoadById } from '../../database/middleware-loader';
import type { AuthContext, AuthUser } from '../../types/user';
import { ENTITY_TYPE_CUSTOM_VIEW, type BasicStoreEntityCustomView } from './customView-types';
import { type CustomViewsDisplayContext, type CustomViewDisplayContext } from '../../generated/graphql';
import {
  ENTITY_TYPE_CONTAINER_NOTE,
  ENTITY_TYPE_CONTAINER_OBSERVED_DATA,
  ENTITY_TYPE_CONTAINER_OPINION,
  ENTITY_TYPE_COURSE_OF_ACTION,
  ENTITY_TYPE_DATA_COMPONENT,
  ENTITY_TYPE_DATA_SOURCE,
  ENTITY_TYPE_LOCATION_CITY,
  ENTITY_TYPE_LOCATION_COUNTRY,
  ENTITY_TYPE_LOCATION_POSITION,
  ENTITY_TYPE_LOCATION_REGION,
} from '../../schema/stixDomainObject';
import { ENTITY_TYPE_SECURITY_COVERAGE } from '../securityCoverage/securityCoverage-types';
import { ENTITY_TYPE_CONTAINER_TASK } from '../task/task-types';
import { ENTITY_TYPE_CONTAINER_FEEDBACK } from '../case/feedback/feedback-types';
import { ABSTRACT_STIX_CORE_RELATIONSHIP, ABSTRACT_STIX_CYBER_OBSERVABLE, ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import { schemaTypesDefinition } from '../../schema/schema-types';
import { ENTITY_HASHED_OBSERVABLE_ARTIFACT } from '../../schema/stixCyberObservable';
import { ENTITY_TYPE_LOCATION_ADMINISTRATIVE_AREA } from '../administrativeArea/administrativeArea-types';

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
  ENTITY_TYPE_LOCATION_CITY,
  ENTITY_TYPE_LOCATION_COUNTRY,
  ENTITY_TYPE_LOCATION_REGION,
  ENTITY_TYPE_LOCATION_ADMINISTRATIVE_AREA,
  ENTITY_TYPE_LOCATION_POSITION,
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

  // if (isFeatureEnabled('DRAFT_WORKFLOW')) {
  //   customTypes.push(ENTITY_TYPE_DRAFT_WORKSPACE);
  // }
  return candidateTypes.includes(entityType)
    && !ENTITY_TYPES_WITHOUT_CUSTOM_VIEWS.includes(entityType);
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
    const { id, name, slug, target_entity_type: targetEntityType } = customViewEntity;
    const infos = infoMap.get(targetEntityType) ?? [];
    // Build the relative path from the slug and the id
    const path = `${slug}-${id.replaceAll('-', '')}`;
    infos.push({ id, path, name });
    infoMap.set(targetEntityType, infos);
    return infoMap;
  }, new Map<string, CustomViewDisplayContext[]>());
  return Array.from(customViewInfoMap.keys()).reduce((acc, targetEntityType) => {
    if (!isCustomViewsAvailableForEntityType(targetEntityType)) {
      return acc;
    }
    const customViewsInfos = customViewInfoMap.get(targetEntityType) ?? [];
    acc.push({
      entity_type: targetEntityType,
      custom_views_info: customViewsInfos,
    });
    return acc;
  }, [] as CustomViewsDisplayContext[]);
};
