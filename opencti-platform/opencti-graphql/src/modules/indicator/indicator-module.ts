import type { ModuleDescriptor } from '../module-descriptor';
import { INDICATOR_DEFINITION } from './indicator';
import indicatorTypeDefs from './indicator.graphql';
import indicatorResolvers from './indicator-resolver';
import { INDICATOR_DECAY_MANAGER_DEFINITION } from '../../manager/indicatorDecayManager';

const indicatorModule: ModuleDescriptor = {
  id: 'indicator',
  dataModel: [INDICATOR_DEFINITION],
  graphqlSchemas: [{ schema: indicatorTypeDefs, resolver: indicatorResolvers }],
  managers: [INDICATOR_DECAY_MANAGER_DEFINITION],
};

export default indicatorModule;
