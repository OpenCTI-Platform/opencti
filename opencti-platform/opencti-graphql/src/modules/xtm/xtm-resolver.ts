import type { Resolvers } from '../../generated/graphql';
import { generateContainerScenario, generateThreatScenario, generateVictimScenario, scenarioElementsDistribution, stixCoreObjectSimulationsResult } from './xtm-domain';

const aiResolvers: Resolvers = {
  Query: {
    obasStixCoreObjectSimulationsResult: (_, args, context) => stixCoreObjectSimulationsResult(context, context.user, args),
    obasScenarioElementsDistribution: (_, args, context) => scenarioElementsDistribution(context, context.user, args),
  },
  Mutation: {
    obasContainerGenerateScenario: (_, args, context) => generateContainerScenario(context, context.user, args),
    obasThreatGenerateScenario: (_, args, context) => generateThreatScenario(context, context.user, args),
    obasVictimGenerateScenario: (_, args, context) => generateVictimScenario(context, context.user, args),
  },
};

export default aiResolvers;
