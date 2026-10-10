import type { ModuleDescriptor } from '../module-descriptor';
import { EXCLUSION_LIST_DEFINITION } from './exclusionList';
import exclusionListTypeDefs from './exclusionList.graphql';
import exclusionListResolver from './exclusionList-resolver';
import { EXCLUSION_LIST_CACHE_BUILD_MANAGER_DEFINITION } from '../../manager/exclusionListCacheBuildManager';
import { EXCLUSION_LIST_CACHE_SYNC_MANAGER } from '../../manager/exclusionListCacheSyncManager';

const exclusionListModule: ModuleDescriptor = {
  id: 'exclusionList',
  dataModel: [EXCLUSION_LIST_DEFINITION],
  graphqlSchemas: [{ schema: exclusionListTypeDefs, resolver: exclusionListResolver }],
  managers: [EXCLUSION_LIST_CACHE_BUILD_MANAGER_DEFINITION, EXCLUSION_LIST_CACHE_SYNC_MANAGER],
};

export default exclusionListModule;
