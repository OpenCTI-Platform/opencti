import type { ModuleDescriptor } from '../module-descriptor';
import { FINTEL_DESIGN_DEFINITION } from './fintelDesign';
import fintelDesignResolvers from './fintelDesign-resolver';
import fintelDesignTypeDefs from './fintelDesign.graphql';

const fintelDesignModule: ModuleDescriptor = {
  id: 'fintelDesign',
  dataModel: [FINTEL_DESIGN_DEFINITION],
  graphqlSchemas: [{ schema: fintelDesignTypeDefs, resolver: fintelDesignResolvers }],
};

export default fintelDesignModule;
