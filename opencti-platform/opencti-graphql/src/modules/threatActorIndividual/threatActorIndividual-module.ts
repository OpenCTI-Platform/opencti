import type { ModuleDescriptor } from '../module-descriptor';
import { THREAT_ACTOR_INDIVIDUAL_DEFINITION } from './threatActorIndividual';
import threatActorIndividualTypeDefs from './threatActorIndividual.graphql';
import threatActorIndividualResolvers from './threatActorIndividual-resolvers';

const threatActorIndividualModule: ModuleDescriptor = {
  id: 'threatActorIndividual',
  dataModel: [THREAT_ACTOR_INDIVIDUAL_DEFINITION],
  graphqlSchemas: [{ schema: threatActorIndividualTypeDefs, resolver: threatActorIndividualResolvers }],
};

export default threatActorIndividualModule;
