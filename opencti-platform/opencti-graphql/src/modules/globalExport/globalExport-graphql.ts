import { registerGraphqlSchema } from '../../graphql/schema';
import globalExportTypeDefs from './globalExport.graphql';
import globalExportResolvers from './globalExport-resolver';

registerGraphqlSchema({
  schema: globalExportTypeDefs,
  resolver: globalExportResolvers,
});
