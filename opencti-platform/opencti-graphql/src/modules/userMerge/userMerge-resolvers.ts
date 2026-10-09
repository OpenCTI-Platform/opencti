import type { AuthContext } from '../../types/user';
import { userMerge, userMergeCoverage, userMergeDeleteSource, userMergeJournal, userMergeSourceDeletionReadiness, type UserMergeOptionsInput } from './userMerge-domain';

const userMergeResolvers = {
  Query: {
    userMergeJournal: (
      _: unknown,
      { mergeId, first }: { mergeId?: string | null; first?: number | null },
      context: AuthContext,
    ) => userMergeJournal(context, context.user!, mergeId, first),
    userMergeCoverage: (
      _: unknown,
      { disposition }: { disposition?: string | null },
      context: AuthContext,
    ) => userMergeCoverage(context, context.user!, disposition),
    userMergeSourceDeletionReadiness: (
      _: unknown,
      { sourceId, targetId }: { sourceId: string; targetId: string },
      context: AuthContext,
    ) => userMergeSourceDeletionReadiness(context, context.user!, sourceId, targetId),
  },
  Mutation: {
    userMerge: (
      _: unknown,
      { sourceId, targetId, options }: { sourceId: string; targetId: string; options?: UserMergeOptionsInput | null },
      context: AuthContext,
    ) => userMerge(context, context.user!, sourceId, targetId, options),
    userMergeDeleteSource: (
      _: unknown,
      { sourceId, targetId }: { sourceId: string; targetId: string },
      context: AuthContext,
    ) => userMergeDeleteSource(context, context.user!, sourceId, targetId),
  },
};

export default userMergeResolvers;
