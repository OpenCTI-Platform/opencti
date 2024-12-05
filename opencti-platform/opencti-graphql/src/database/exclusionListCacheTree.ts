import { type BasicStoreEntityExclusionList, ENTITY_TYPE_EXCLUSION_LIST } from '../modules/exclusionList/exclusionList-types';
import { addExclusionListToTree, checkExclusionListTree, type ExclusionListNode } from '../utils/exclusionLists';
import type { AuthContext } from '../types/user';
import { listAllEntities } from './middleware-loader';
import { SYSTEM_USER } from '../utils/access';
import { getFileContent } from './file-storage';
import { logApp, NODE_INSTANCE_ID } from '../config/conf';
import { redisUpdateExclusionListStatus } from './redis';

let exclusionListCacheTree: ExclusionListNode | null = null;

const buildTreeFromAllExclusionLists = async (context: AuthContext) => {
  const exclusionLists: BasicStoreEntityExclusionList[] = await listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_EXCLUSION_LIST]);
  const enabledExclusionLists = exclusionLists.filter((l) => l.enabled);
  const enabledExclusionListsCount = enabledExclusionLists.length;
  const builtTree: ExclusionListNode = { matchedLists: [], nextNodes: new Map() };
  if (enabledExclusionListsCount === 0) return builtTree;

  for (let i = 0; i < enabledExclusionListsCount; i += 1) {
    const currentExclusionList = enabledExclusionLists[i];
    try {
      const currentExclusionFileContent = await getFileContent(currentExclusionList.file_id, 'utf8');
      if (currentExclusionFileContent) {
        await addExclusionListToTree(builtTree, currentExclusionList.id, currentExclusionList.exclusion_list_entity_types, currentExclusionFileContent);
      }
    } catch (e) {
      logApp.error('[OPENCTI-MODULE][EXCLUSION-BUILD-MANAGER] Exclusion list could not be built properly.', { cause: e, exclusionList: currentExclusionList });
    }
  }
  return builtTree;
};

export const initExclusionListCache = async (context: AuthContext | null) => {
  exclusionListCacheTree = context ? await buildTreeFromAllExclusionLists(context) : { matchedLists: [], nextNodes: new Map() };
};

export const rebuildExclusionListCache = async (context: AuthContext, cacheDate: string) => {
  exclusionListCacheTree = await buildTreeFromAllExclusionLists(context);
  const exclusionListStatus = { [NODE_INSTANCE_ID]: cacheDate };
  await redisUpdateExclusionListStatus(exclusionListStatus);
};

export const checkExclusionListCacheTree = (valueToCheck: string, valueToCheckType: string) => {
  return checkExclusionListTree(exclusionListCacheTree, valueToCheck, valueToCheckType);
};
