import { type BasicStoreEntityExclusionList, ENTITY_TYPE_EXCLUSION_LIST } from '../modules/exclusionList/exclusionList-types';
import { ENTITY_IPV4_ADDR, ENTITY_IPV6_ADDR } from '../schema/stixCyberObservable';
import { checkExclusionLists, convertIpAddr } from '../utils/exclusionLists';
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
  ranges?: number[] // only used for IPs
}

let exclusionListCache: ExclusionListCacheItem[] | null = null;

export const getIsCacheInitialized = (): boolean => exclusionListCache !== null;

const isIPExclusionList = (exclusionList: BasicStoreEntityExclusionList) => {
  // TODO is it possible to have a list with a mix of IP and other?
  return exclusionList.exclusion_list_entity_types.some((t) => ENTITY_IPV4_ADDR === t || ENTITY_IPV6_ADDR === t);
};

const buildIPExclusionListCacheItem = async (exclusionList: BasicStoreEntityExclusionList, exclusionListFileValues: string[]) => {
  const convertedValues = convertIpAddr(exclusionListFileValues);

  const exclusionLists = [];
  if (convertedValues.ipv4.values.length > 0) {
    const ipv4ranges = convertedValues.ipv4.ranges;
    // TODO handle event loop block?
    const ipv4values = convertedValues.ipv4.values.sort();
    const ipv4ExclusionList = { id: exclusionList.id, types: [ENTITY_IPV4_ADDR], values: ipv4values, ranges: ipv4ranges };
    exclusionLists.push(ipv4ExclusionList);
  }
  if (convertedValues.ipv6.values.length > 0) {
    const ipv6ranges = convertedValues.ipv6.ranges;
    // TODO handle event loop block ?
    const ipv6values = convertedValues.ipv6.values.sort();
    const ipv6ExclusionList = { id: exclusionList.id, types: [ENTITY_IPV6_ADDR], values: ipv6values, ranges: ipv6ranges };
    exclusionLists.push(ipv6ExclusionList);
  }

  return exclusionLists;
};

const buildExclusionListCacheItem = async (exclusionList: BasicStoreEntityExclusionList, exclusionListFileContent: string | undefined) => {
  const exclusionListFileValues = exclusionListFileContent?.split(/\r\n|\n/).map((l) => l.trim()).filter((l) => l);
  if (!exclusionListFileValues) {
    return [];
  }

  if (isIPExclusionList(exclusionList)) {
    return buildIPExclusionListCacheItem(exclusionList, exclusionListFileValues);
  }

  // TODO handle event loop block ?
  const sortedValues = exclusionListFileValues.sort();
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
      const currentExclusionListCacheItem = await buildExclusionListCacheItem(currentExclusionList, currentExclusionFileContent);
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
  if (!exclusionListCache) {
    throw FunctionalError('Failed to load exclusion list cache.', { exclusionListCache });
  }
  return checkExclusionLists(value, type, exclusionListCache);
};
