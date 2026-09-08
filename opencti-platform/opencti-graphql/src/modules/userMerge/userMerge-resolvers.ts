import type { AuthContext } from '../../types/user';
import { userMerge, userMergeJournal, type UserMergeOptionsInput } from './userMerge-domain';

const userMergeResolvers = {
  Query: {
    userMergeJournal: (
      _: unknown,
      { mergeId, first }: { mergeId?: string | null; first?: number | null },
      context: AuthContext,
    ) => userMergeJournal(context, context.user!, mergeId, first),
  },
  Mutation: {
    userMerge: (
      _: unknown,
      { sourceId, targetId, options }: { sourceId: string; targetId: string; options?: UserMergeOptionsInput | null },
      context: AuthContext,
    ) => userMerge(context, context.user!, sourceId, targetId, options),
  },
};

export default userMergeResolvers;
