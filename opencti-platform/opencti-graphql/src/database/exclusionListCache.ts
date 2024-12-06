import { type BasicStoreEntityExclusionList, ENTITY_TYPE_EXCLUSION_LIST } from '../modules/exclusionList/exclusionList-types';
import { ENTITY_IPV4_ADDR, ENTITY_IPV6_ADDR } from '../schema/stixCyberObservable';
import { checkExclusionList, checkIpAddressLists, checkIpAddrType, convertIpAddr, reverseString } from '../utils/exclusionLists';
import type { AuthContext } from '../types/user';
import { listAllEntities } from './middleware-loader';
import { SYSTEM_USER } from '../utils/access';
import { getFileContent } from './file-storage';
import { logApp, PLATFORM_INSTANCE_ID } from '../config/conf';
import { redisGetExclusionListCache, redisSetExclusionListCache, redisUpdateExclusionListStatus } from './redis';
import { FunctionalError } from '../config/errors';

export interface ExclusionListCacheItem {
  id: string
  types: string[]
  values: string[]
}

let exclusionListCache: ExclusionListCacheItem[] | null = null;

export const getIsCacheInitialized = (): boolean => exclusionListCache !== null;

const getCache = (entityType: string = ''): ExclusionListCacheItem[] | null => {
  return entityType && exclusionListCache ? exclusionListCache.filter((e) => e.types.includes(entityType)) : exclusionListCache;
};

const isIPExclusionList = (exclusionList: BasicStoreEntityExclusionList) => {
  // TODO is it possible to have a list with a mix of IP and other?
  return exclusionList.exclusion_list_entity_types.some((t) => ENTITY_IPV4_ADDR === t || ENTITY_IPV6_ADDR === t);
};

const buildIPExclusionListCacheItem = (exclusionList: BasicStoreEntityExclusionList, exclusionListFileValues: string[]) => {
  const ipv4Values = exclusionListFileValues.filter((i) => checkIpAddrType(i).isIpv4);
  const ipv4ConvertedValues = convertIpAddr(ipv4Values).sort();
  const ipv4List = { id: exclusionList.id, types: [ENTITY_IPV4_ADDR], values: ipv4ConvertedValues };

  const ipv6Values = exclusionListFileValues.filter((i) => checkIpAddrType(i).isIpv6);
  const ipv6ConvertedValues = convertIpAddr(ipv4Values).sort();
  const ipv6List = { id: exclusionList.id, types: [ENTITY_IPV6_ADDR], values: ipv6ConvertedValues };

  const ipLists = [];

  if (ipv4Values.length > 0) {
    ipLists.push(ipv4List);
  }
  if (ipv6Values.length > 0) {
    ipLists.push(ipv6List);
  }
  return ipLists;
};

const buildExclusionListCacheItem = (exclusionList: BasicStoreEntityExclusionList, exclusionListFileContent: string | undefined) => {
  const exclusionListFileValues = exclusionListFileContent?.split(/\r\n|\n/).map((l) => l.trim()).filter((l) => l);
  if (!exclusionListFileValues) {
    return [];
  }

  if (isIPExclusionList(exclusionList)) {
    return buildIPExclusionListCacheItem(exclusionList, exclusionListFileValues);
  }

  const sortedValues = exclusionListFileValues.map((v) => reverseString(v)).sort();
  return [{ id: exclusionList.id, types: exclusionList.exclusion_list_entity_types, values: sortedValues }];
};

export const buildCacheFromAllExclusionLists = async (context: AuthContext) => {
  const exclusionLists: BasicStoreEntityExclusionList[] = await listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_EXCLUSION_LIST]);
  const enabledExclusionLists = exclusionLists.filter((l) => l.enabled);
  const exclusionListsCount = enabledExclusionLists.length;
  const builtCache: ExclusionListCacheItem[] = [];
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
export const initExclusionListCache = async () => {
  exclusionListCache = await redisGetExclusionListCache();
};

export const rebuildExclusionListCache = async (context: AuthContext, cacheDate: string) => {
  exclusionListCache = await buildCacheFromAllExclusionLists(context);
  await redisSetExclusionListCache(exclusionListCache);
  const exclusionListStatus = { last_cache_date: cacheDate, [PLATFORM_INSTANCE_ID]: cacheDate };
  await redisUpdateExclusionListStatus(exclusionListStatus);
};

export const syncExclusionListCache = async (cacheDate: string) => {
  exclusionListCache = await redisGetExclusionListCache();
  await redisUpdateExclusionListStatus({ [PLATFORM_INSTANCE_ID]: cacheDate });
};

export const checkObservableValue = async (observableValue: any) => {
  const { type, value } = observableValue;
  if (!type || !value) {
    return null;
  }
  const relatedLists = getCache(type);
  if (!relatedLists) {
    throw FunctionalError('Failed to load exclusion list cache.', { relatedLists, type });
  }
  const isIpType = type === ENTITY_IPV4_ADDR || type === ENTITY_IPV6_ADDR;
  return (isIpType ? checkIpAddressLists(value, relatedLists) : checkExclusionList(value, relatedLists));
};
