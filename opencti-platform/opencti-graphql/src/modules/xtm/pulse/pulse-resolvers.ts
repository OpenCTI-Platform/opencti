import type { Resolvers } from '../../../generated/graphql';
import type { AuthContext } from '../../../types/user';
import {
  configurePulse,
  getPulseBenchmark,
  getPulseEntityInformation,
  getPulseSettings,
  getPulseStatus,
  getPulseTrending,
  purgePulseContributions,
  recordPulseTelemetry,
  resolvePulseField,
  resolvePulseStatusPreview,
} from './pulse-domain';
import type { BasicStorePulseEntity, PulsePeriodValue, PulseRegionBucketValue, PulseSectorBucketValue } from './pulse-types';

const pulseField = {
  pulse: (entity: unknown, _: unknown, context: AuthContext) => resolvePulseField(context, entity as BasicStorePulseEntity),
};

const pulseResolvers: Resolvers = {
  Query: {
    pulseStatus: (_, __, context) => getPulseStatus(context),
    pulseSettings: (_, __, context) => getPulseSettings(context),
    pulseEntity: (_, { id }, context) => getPulseEntityInformation(context, context.user, id),
    pulseTrending: (_, args, context) => getPulseTrending(context, context.user, {
      period: args.period as PulsePeriodValue,
      sector_bucket: args.sector_bucket as PulseSectorBucketValue | null | undefined,
      region_bucket: args.region_bucket as PulseRegionBucketValue | null | undefined,
      entity_types: args.entity_types,
      first: args.first,
      include_preview: args.include_preview,
    }),
    pulseBenchmark: (_, args, context) => getPulseBenchmark(context, context.user, { period: args.period as PulsePeriodValue }),
  },
  Mutation: {
    pulseConfigure: (_, { input }, context) => configurePulse(context, context.user, input),
    pulsePurge: (_, __, context) => purgePulseContributions(context, context.user),
    pulseTelemetry: (_, { event, surface }, context) => recordPulseTelemetry(context, event, surface),
  },
  PulseStatus: {
    preview_entities: async (status, _, context) => (await resolvePulseStatusPreview(context, context.user, status)).entities,
    preview_since: async (status, _, context) => (await resolvePulseStatusPreview(context, context.user, status)).since,
  },
  Indicator: pulseField,
  AttackPattern: pulseField,
  Vulnerability: pulseField,
  IntrusionSet: pulseField,
  Malware: pulseField,
  Tool: pulseField,
};

export default pulseResolvers;
