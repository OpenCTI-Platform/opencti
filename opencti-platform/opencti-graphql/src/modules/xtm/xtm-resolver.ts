import type { Resolvers } from '../../generated/graphql';
import {
  generateContainerScenarioWithInjectPlaceholders,
  generateThreatScenarioWithInjectPlaceholders,
  generateVictimScenarioWithInjectPlaceholders,
  scenarioElementsDistribution,
  stixCoreObjectSimulationsResult
} from './xtm-domain';

const aiResolvers: Resolvers = {
  Query: {
    obasStixCoreObjectSimulationsResult: (_, args, context) => stixCoreObjectSimulationsResult(context, context.user, args),
    obasScenarioElementsDistribution: (_, args, context) => scenarioElementsDistribution(context, context.user, args),
  },
  Mutation: {
    obasContainerGenerateScenarioWithInjectPlaceholders: (_, args, context) => generateContainerScenarioWithInjectPlaceholders(context, context.user, args),
    obasThreatGenerateScenarioWithInjectPlaceholders: (_, args, context) => generateThreatScenarioWithInjectPlaceholders(context, context.user, args),
    obasVictimGenerateScenarioWithInjectPlaceholders: (_, args, context) => generateVictimScenarioWithInjectPlaceholders(context, context.user, args),
  },
};

export default aiResolvers;
