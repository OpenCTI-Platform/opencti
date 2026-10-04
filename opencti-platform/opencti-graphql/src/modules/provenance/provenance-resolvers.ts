import type { Resolvers } from '../../generated/graphql';
import type { AuthContext, AuthUser } from '../../types/user';
import {
  adoptConflictValue,
  adoptProcedure,
  assertElement,
  computeFreshnessDays,
  dismissConflictValue,
  provenanceBackfillRestart,
  provenanceBackfillStatus,
  provenanceFreshnessDistribution,
  provenanceSingleSourcedByType,
  provenanceSourceKindsDistribution,
  provenanceStatistics,
  resolveAssertionsForUser,
  resolveConflictsForUser,
} from './provenance-domain';
import type { StoreAssertion, StoreConflict } from './provenance-types';

type ProvenanceHolder = {
  entity_type?: string;
  last_asserted_at?: string | null;
  x_opencti_assertions?: StoreAssertion[] | null;
  x_opencti_conflicts?: StoreConflict[] | null;
};

const provenanceFieldsResolvers = {
  freshness_days: (element: ProvenanceHolder) => computeFreshnessDays(element.last_asserted_at),
  x_opencti_assertions: (element: ProvenanceHolder, _: unknown, context: AuthContext) => {
    return resolveAssertionsForUser(context, context.user as AuthUser, element.x_opencti_assertions);
  },
  x_opencti_conflicts: (element: ProvenanceHolder, _: unknown, context: AuthContext) => {
    return resolveConflictsForUser(context, context.user as AuthUser, element.x_opencti_conflicts, element.entity_type);
  },
};

const provenanceResolvers: Resolvers = {
  Query: {
    provenanceStatistics: (_, args, context) => provenanceStatistics(context, context.user, args),
    provenanceFreshnessDistribution: (_, args, context) => provenanceFreshnessDistribution(context, context.user, args),
    provenanceSourceKindsDistribution: (_, args, context) => provenanceSourceKindsDistribution(context, context.user, args) as any,
    provenanceSingleSourcedByType: (_, args, context) => provenanceSingleSourcedByType(context, context.user, args),
    provenanceBackfill: (_, __, context) => provenanceBackfillStatus(context) as any,
  },
  // Results are resolved through the StixObjectOrStixRelationship union, stricter than the store types
  Mutation: {
    provenanceConflictAdopt: (_, { id, field, value_hash }, context) => adoptConflictValue(context, context.user, id, field, value_hash) as any,
    provenanceConflictDismiss: (_, { id, field, value_hash }, context) => dismissConflictValue(context, context.user, id, field, value_hash) as any,
    provenanceProcedureAdopt: (_, { id, text }, context) => adoptProcedure(context, context.user, id, text) as any,
    provenanceAssert: (_, { id }, context) => assertElement(context, context.user, id) as any,
    provenanceBackfillRestart: (_, __, context) => provenanceBackfillRestart(context, context.user) as any,
  },
  // Inherited by every implementation of the interface (inheritResolversFromInterfaces)
  StixCoreObject: provenanceFieldsResolvers as any,
  StixCoreRelationship: provenanceFieldsResolvers as any,
  StixSightingRelationship: provenanceFieldsResolvers as any,
  SourceConflictValue: {
    adoptable: (value) => value.value !== null && value.value !== undefined,
  },
};

export default provenanceResolvers;
