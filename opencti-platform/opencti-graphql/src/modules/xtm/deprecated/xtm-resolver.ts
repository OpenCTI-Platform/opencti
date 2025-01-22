import type { Resolvers } from '../../../generated/graphql';
import { generateContainerScenario, generateThreatScenario, generateVictimScenario } from './xtm-domain';

const aiResolvers_deprecated: Resolvers = {
  Mutation: {
    obasContainerGenerateScenario: (_, args, context) => generateContainerScenario(context, context.user, args),
    obasThreatGenerateScenario: (_, args, context) => generateThreatScenario(context, context.user, args),
    obasVictimGenerateScenario: (_, args, context) => generateVictimScenario(context, context.user, args),
  },
};

export default aiResolvers_deprecated;
