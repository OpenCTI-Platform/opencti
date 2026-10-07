import { registerGraphqlSchema } from '../../graphql/schema';
import timeMachineTypeDefs from './timeMachine.graphql';
import timeMachineResolvers from './timeMachine-resolvers';

registerGraphqlSchema({
  schema: timeMachineTypeDefs,
  resolver: timeMachineResolvers,
});
