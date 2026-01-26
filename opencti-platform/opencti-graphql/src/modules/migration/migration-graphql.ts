import { registerGraphqlSchema } from '../../graphql/schema';
import migrationDefs from '../migration/migration.graphql';
import migrationResolvers from './migration-resolver';

registerGraphqlSchema({
  schema: migrationDefs,
  resolver: migrationResolvers,
});
