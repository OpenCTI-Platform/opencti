import { registerGraphqlSchema } from '../../graphql/schema';
import intelligenceRequirementTypeDefs from './intelligenceRequirement.graphql';
import intelligenceRequirementResolvers from './intelligenceRequirement-resolvers';

registerGraphqlSchema({
  schema: intelligenceRequirementTypeDefs,
  resolver: intelligenceRequirementResolvers,
});
