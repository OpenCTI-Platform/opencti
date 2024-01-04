import { registerGraphqlSchema } from '../../../graphql/schema';
import caseIncidentTypeDefs from './case-incident.graphql';
import caseIncidentResolvers from './case-incident-resolvers';

registerGraphqlSchema({
  schema: caseIncidentTypeDefs,
  resolver: caseIncidentResolvers,
});
