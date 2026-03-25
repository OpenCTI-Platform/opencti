import type { AuthContext, AuthUser } from '../../types/user';
import { fullEntitiesList, pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import { type BasicStoreEntityCustomView, ENTITY_TYPE_CUSTOM_VIEW } from './customView-types';
import { createEntity, deleteElementById } from '../../database/middleware';
import type { CustomViewAddInput, CustomViewDisplayContext, CustomViewsDisplayContext, CustomViewsSettingsPaginationOptions } from '../../generated/graphql';
import { ENTITY_TYPE_CONTAINER_GROUPING } from '../grouping/grouping-types';
import { ENTITY_TYPE_MALWARE_ANALYSIS } from '../malwareAnalysis/malwareAnalysis-types';
import {
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_INCIDENT,
  ENTITY_TYPE_INFRASTRUCTURE,
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_MALWARE,
  ENTITY_TYPE_TOOL,
  ENTITY_TYPE_VULNERABILITY,
} from '../../schema/stixDomainObject';
import { ENTITY_TYPE_CHANNEL } from '../channel/channel-types';
import { ENTITY_TYPE_CONTAINER_CASE } from '../case/case-types';
import { ENTITY_TYPE_EVENT } from '../event/event-types';
import { ABSTRACT_STIX_CYBER_OBSERVABLE, ENTITY_TYPE_IDENTITY, ENTITY_TYPE_LOCATION, ENTITY_TYPE_THREAT_ACTOR } from '../../schema/general';
import { ENTITY_TYPE_INDICATOR } from '../indicator/indicator-types';
import { ENTITY_TYPE_NARRATIVE } from '../narrative/narrative-types';
import { schemaTypesDefinition } from '../../schema/schema-types';
import { emptyPaginationResult } from '../../database/utils';
import { addFilter } from '../../utils/filtering/filtering-utils';

/**
 * Stix Domain Object types allowed to have a custom view
 */
const ENTITY_TYPES_WITH_CUSTOM_VIEWS = [
  ENTITY_TYPE_CONTAINER_GROUPING,
  ENTITY_TYPE_MALWARE_ANALYSIS,
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_CHANNEL,
  ENTITY_TYPE_MALWARE,
  ENTITY_TYPE_TOOL,
  ENTITY_TYPE_VULNERABILITY,
  ENTITY_TYPE_CONTAINER_CASE,
  ENTITY_TYPE_EVENT,
  ENTITY_TYPE_IDENTITY,
  ENTITY_TYPE_LOCATION,
  ENTITY_TYPE_INCIDENT,
  ENTITY_TYPE_INDICATOR,
  ENTITY_TYPE_INFRASTRUCTURE,
  ABSTRACT_STIX_CYBER_OBSERVABLE,
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_NARRATIVE,
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_THREAT_ACTOR,
];

function isCustomViewsAvailableForEntityType(entityType: string) {
  return ENTITY_TYPES_WITH_CUSTOM_VIEWS.includes(entityType)
    || ENTITY_TYPES_WITH_CUSTOM_VIEWS.some((e) => schemaTypesDefinition.isTypeIncludedIn(entityType, e));
}

// View Use Cases (all authed users)

export const getCustomViewById = async (context: AuthContext, user: AuthUser, customViewId: string) => {
  return storeLoadById<BasicStoreEntityCustomView>(
    context,
    user,
    customViewId,
    ENTITY_TYPE_CUSTOM_VIEW,
  );
};

export const getCustomViewsContext = async (context: AuthContext, user: AuthUser) => {
  const allCustomViewEntities = await fullEntitiesList<BasicStoreEntityCustomView>(context, user, [ENTITY_TYPE_CUSTOM_VIEW]);
  const customViewInfoMap = allCustomViewEntities.reduce((infoMap, customViewEntity) => {
    const targetEntityType = customViewEntity.target_entity_type;
    const infos = infoMap.get(targetEntityType) ?? [];
    infos.push({
      id: customViewEntity.id,
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

export const getCustomViewsSettings = async (
  context: AuthContext,
  user: AuthUser,
  entityType: string,
  options: CustomViewsSettingsPaginationOptions,
) => {
  if (!isCustomViewsAvailableForEntityType(entityType)) {
    return {
      canEntityTypeHaveCustomViews: false,
      customViews: emptyPaginationResult<BasicStoreEntityCustomView>(),
    };
  }
  const filters = addFilter(undefined, 'target_entity_type', [entityType]);
  const customViews = await pageEntitiesConnection(
    context,
    user,
    [ENTITY_TYPE_CUSTOM_VIEW],
    {
      ...options,
      filters,
    },
  );
  return {
    canEntityTypeHaveCustomViews: true,
    customViews,
  };
};

export const addCustomView = async (
  context: AuthContext,
  user: AuthUser,
  input: CustomViewAddInput,
) => {
  const customViewToCreate = {
    ...input,
  };

  return createEntity(
    context,
    user,
    customViewToCreate,
    ENTITY_TYPE_CUSTOM_VIEW,
  );
};

export const customViewDelete = async (
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
