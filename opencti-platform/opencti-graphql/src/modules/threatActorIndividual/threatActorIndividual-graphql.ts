import { registerGraphqlSchema } from '../../graphql/schema';
import threatActorIndividualTypeDefs from './threatActorIndividual.graphql';
import threatActorIndividualResolvers from './threatActorIndividual-resolvers';

registerGraphqlSchema({
  schema: threatActorIndividualTypeDefs,
  resolver: threatActorIndividualResolvers,
});
