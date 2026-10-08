import type { Resolvers } from '../../generated/graphql';
import {
  addPlatformProvidesFromLogsources,
  buildDefenseMatrix,
  coveragePlatformsInformationForReader,
  defenseGapRequiredDataComponents,
  defenseGapRuleCandidates,
  defenseGapValidationCoverage,
  defenseGapValidationStatus,
  defenseTechniqueDataComponents,
  defenseTechniqueGaps,
  defenseTechniqueMitigations,
  defenseTechniqueRules,
  defenseTechniqueThreats,
  defenseTechniqueValidations,
  exportDefenseGaps,
  findDefenseGaps,
  findDefensePlatforms,
  findDefenseTechnique,
  getDefenseCoverageStatus,
  requestDefenseCoverageRecompute,
  resolveMappingDataComponents,
  validateDefenseGaps,
} from './defenseCoverage-domain';
import {
  addDefenseLogsourceMapping,
  deleteDefenseLogsourceMapping,
  fieldPatchDefenseLogsourceMapping,
  findById as findLogsourceMappingById,
  findDefenseLogsourceMappingPaginated,
  resetDefenseLogsourceMappings,
} from './defenseLogsourceMapping/defenseLogsourceMapping-domain';
import type { DefenseThreatScope } from './defenseCoverage-reader';

const defenseCoverageResolvers: Resolvers = {
  Query: {
    defensePlatforms: (_, __, context) => findDefensePlatforms(context, context.user),
    defenseMatrix: (_, args, context) => buildDefenseMatrix(context, context.user, {
      platformIds: args.platformIds,
      threatScope: args.threatScope as DefenseThreatScope | null | undefined,
    }),
    defenseTechnique: (_, args, context) => findDefenseTechnique(context, context.user, args.id, {
      platformIds: args.platformIds,
      threatScope: args.threatScope as DefenseThreatScope | null | undefined,
    }),
    defenseGaps: (_, args, context) => findDefenseGaps(context, context.user, {
      ...args,
      threatScope: args.threatScope as DefenseThreatScope | null | undefined,
    }),
    defenseGapExport: (_, args, context) => exportDefenseGaps(context, context.user, {
      ...args,
      threatScope: args.threatScope as DefenseThreatScope | null | undefined,
    }),
    defenseCoverageStatus: (_, __, context) => getDefenseCoverageStatus(context, context.user),
    defenseLogsourceMapping: (_, { id }, context) => findLogsourceMappingById(context, context.user, id),
    defenseLogsourceMappings: (_, args, context) => findDefenseLogsourceMappingPaginated(context, context.user, args),
  },
  DefenseTechnique: {
    dataComponents: (view, _, context) => defenseTechniqueDataComponents(context, context.user, view),
    rules: (view, _, context) => defenseTechniqueRules(context, context.user, view),
    validations: (view, _, context) => defenseTechniqueValidations(context, context.user, view),
    mitigations: (view, _, context) => defenseTechniqueMitigations(context, context.user, view),
    threats: (view, _, context) => defenseTechniqueThreats(context, context.user, view),
    gaps: (view, _, context) => defenseTechniqueGaps(context, context.user, view),
  },
  DefenseGap: {
    attackPattern: (gap, _, context) => context.batch.idsBatchLoader.load({ id: gap.attack_pattern_id }),
    requiredDataComponents: (gap, _, context) => defenseGapRequiredDataComponents(context, context.user, gap),
    ruleCandidates: (gap, { first }, context) => defenseGapRuleCandidates(context, context.user, gap, first),
  },
  DefenseValidationRequest: {
    securityCoverage: (request, _, context) => defenseGapValidationCoverage(context, context.user, request),
    status: (request, _, context) => defenseGapValidationStatus(context, context.user, request),
  },
  StixCoreRelationship: {
    coverage_platforms_information: (relation, _, context) => coveragePlatformsInformationForReader(
      context,
      context.user,
      (relation as unknown as { coverage_platforms_information?: { platform_ref: string; coverage_name: string; coverage_score: number }[] | null }).coverage_platforms_information,
    ),
  },
  DefenseLogsourceMapping: {
    logsource_category: (mapping) => mapping.x_opencti_rule_logsource?.category ?? null,
    logsource_product: (mapping) => mapping.x_opencti_rule_logsource?.product ?? null,
    logsource_service: (mapping) => mapping.x_opencti_rule_logsource?.service ?? null,
    resolvedDataComponents: (mapping, _, context) => resolveMappingDataComponents(context, context.user, mapping.data_components),
  },
  Mutation: {
    defenseGapsValidate: (_, { input }, context) => validateDefenseGaps(context, context.user, input),
    defenseCoverageRecompute: () => requestDefenseCoverageRecompute(),
    defensePlatformProvidesFromLogsources: (_, { id, logsources }, context) => addPlatformProvidesFromLogsources(context, context.user, id, logsources),
    defenseLogsourceMappingAdd: (_, { input }, context) => addDefenseLogsourceMapping(context, context.user, input),
    defenseLogsourceMappingFieldPatch: (_, { id, input }, context) => fieldPatchDefenseLogsourceMapping(context, context.user, id, input),
    defenseLogsourceMappingDelete: (_, { id }, context) => deleteDefenseLogsourceMapping(context, context.user, id),
    defenseLogsourceMappingsReset: (_, __, context) => resetDefenseLogsourceMappings(context, context.user),
  },
};

export default defenseCoverageResolvers;
