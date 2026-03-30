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
    const targetEntityType = customViewEntity.target_entity_type;
    const infos = infoMap.get(targetEntityType) ?? [];
    infos.push({
      id: customViewEntity.id,
      path: customViewEntity.path,
      name: customViewEntity.name,
    });
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

// Settings Use Cases (admin users)

// export const getCustomViewsSettings = async (
//   context: AuthContext,
//   user: AuthUser,
//   entityType: string,
// ) => {
//   if (!isCustomViewsAvailableForEntityType(entityType)) {
//     return {
//       can_have_custom_views: false,
//       custom_views_info: [],
//     };
//   }
//   const customViewEntities = await fullEntitiesList<BasicStoreEntityCustomView>(
//     context,
//     user,
//     [ENTITY_TYPE_CUSTOM_VIEW],
//     {
//       filters: {
//         mode: FilterMode.And,
//         filters: [{ key: ['target_entity_type'], values: [entityType] }],
//         filterGroups: [],
//       },
//     });
//   return {
//     can_have_custom_views: true,
//     custom_views_info: customViewEntities.map((entity) => ({
//       id: entity.id,
//       name: entity.name,
//       path: entity.path,
//       description: entity.description,
//       created_at: entity.created_at,
//       updated_at: entity.updated_at,
//     })),
//   };
// };
