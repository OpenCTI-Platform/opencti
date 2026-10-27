import type { ModuleDescriptor } from '../module-descriptor';
import { DATA_SANITY_DEFINITION } from './dataSanity';
import dataSanityTypeDefs from './dataSanity.graphql';
import dataSanityResolvers from './dataSanity-resolvers';
import { DATA_SANITY_MANAGER_DEFINITION } from '../../manager/dataSanityManager';

const dataSanityModule: ModuleDescriptor = {
  id: 'dataSanity',
  definitions: [DATA_SANITY_DEFINITION],
  graphqlSchemas: [{ schema: dataSanityTypeDefs, resolver: dataSanityResolvers }],
  managers: [DATA_SANITY_MANAGER_DEFINITION],
};

export default dataSanityModule;
