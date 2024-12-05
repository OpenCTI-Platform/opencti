import { type BasicStoreEntityExclusionList, ENTITY_TYPE_EXCLUSION_LIST } from '../modules/exclusionList/exclusionList-types';
import { ENTITY_IPV4_ADDR, ENTITY_IPV6_ADDR } from '../schema/stixCyberObservable';
import { checkExclusionList, checkIpAddressLists, checkIpAddrType, convertIpAddr } from '../utils/exclusionLists';
import type { AuthContext } from '../types/user';
import { listAllEntities } from './middleware-loader';
import { SYSTEM_USER } from '../utils/access';
import { getFileContent } from './file-storage';
import { logApp } from '../config/conf';
import { redisGetExclusionListCache, redisSetExclusionListCache, redisUpdateExclusionListStatus } from './redis';
import { FunctionalError } from '../config/errors';

export interface ExclusionListSlowCacheItem {
  id: string
  types: string[]
  values: string[]
}

let exclusionListCache: ExclusionListSlowCacheItem[] | null = null;

const getSlowCache = (entityType: string = ''): ExclusionListSlowCacheItem[] | null => {
  return entityType && exclusionListCache ? exclusionListCache.filter((e) => e.types.includes(entityType)) : exclusionListCache;
};

const isIPExclusionList = (exclusionList: BasicStoreEntityExclusionList) => {
  // TODO is it possible to have a list with a mix of IP and other?
  return exclusionList.exclusion_list_entity_types.some((t) => ENTITY_IPV4_ADDR === t || ENTITY_IPV6_ADDR === t);
};

const buildExclusionListCacheItem = (exclusionList: BasicStoreEntityExclusionList, exclusionListFileContent: string | undefined) => {
  const exclusionListFileValues = exclusionListFileContent?.split(/\r\n|\n/).map((l) => l.trim()).filter((l) => l);
  if (exclusionListFileValues && isIPExclusionList(exclusionList)) {
    const ipv4Values = exclusionListFileValues.filter((i) => checkIpAddrType(i).isIpv4);
    const ipv4ConvertedValues = ipv4Values.map((i) => convertIpAddr(i));
    const ipv4List = { id: exclusionList.id, types: [ENTITY_IPV4_ADDR], values: ipv4ConvertedValues };

    const ipv6Values = exclusionListFileValues.filter((i) => checkIpAddrType(i).isIpv6);
    const ipv6ConvertedValues = ipv6Values.map((i) => convertIpAddr(i));
    const ipv6List = { id: exclusionList.id, types: [ENTITY_IPV6_ADDR], values: ipv6ConvertedValues };

    const ipLists = [];

    if (ipv4Values.length > 0) {
      ipLists.push(ipv4List);
    }
    if (ipv6Values.length > 0) {
      ipLists.push(ipv6List);
    }
    return ipLists;
  }
  return [{ id: exclusionList.id, types: exclusionList.exclusion_list_entity_types, values: exclusionListFileValues ?? [] }];
};

export const buildSlowCacheFromAllExclusionLists = async (context: AuthContext) => {
  const exclusionLists: BasicStoreEntityExclusionList[] = await listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_EXCLUSION_LIST]);
  const enabledExclusionLists = exclusionLists.filter((l) => l.enabled);
  const exclusionListsCount = enabledExclusionLists.length;
  const builtCache: ExclusionListSlowCacheItem[] = [];
  for (let i = 0; i < exclusionListsCount; i += 1) {
    const currentExclusionList = enabledExclusionLists[i];
    try {
      const currentExclusionFileContent = await getFileContent(currentExclusionList.file_id);
      const currentExclusionListCacheItem = buildExclusionListCacheItem(currentExclusionList, currentExclusionFileContent);
      builtCache.push(...currentExclusionListCacheItem);
    } catch (e) {
      logApp.error('[OPENCTI-MODULE][EXCLUSION-BUILD-MANAGER] Exclusion list could not be built properly.', { cause: e, exclusionList: currentExclusionList });
    }
  }
  return builtCache;
};

// cache is always initialized as an empty array if there is no redis data: we might want to change it to rebuild cache locally as a failsafe is there is no redis data
export const initExclusionListCacheSlow = async () => {
  exclusionListCache = await redisGetExclusionListCache();
};

export const rebuildExclusionListCacheSlow = async (context: AuthContext, cacheDate: string) => {
  const newCache = await buildSlowCacheFromAllExclusionLists(context);
  exclusionListCache = newCache;
  await redisSetExclusionListCache(newCache);
  const exclusionListStatus = { last_cache_date: cacheDate };
  await redisUpdateExclusionListStatus(exclusionListStatus);
};

export const checkExclusionListCacheSlow = async (valueToCheck: string, valueToCheckType: string) => {
  const relatedLists = getSlowCache(valueToCheckType);
  if (!relatedLists) {
    throw FunctionalError('Failed to load exclusion list cache.', { relatedLists, valueToCheckType });
  }
  const isIpType = valueToCheckType === ENTITY_IPV4_ADDR || valueToCheckType === ENTITY_IPV6_ADDR;
  const listCheck = await (isIpType ? checkIpAddressLists(valueToCheck, relatedLists) : checkExclusionList(valueToCheck, relatedLists));
  return listCheck;
};
