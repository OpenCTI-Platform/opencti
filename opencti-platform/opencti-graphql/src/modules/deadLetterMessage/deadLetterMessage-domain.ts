import type { AuthContext, AuthUser } from '../../types/user';
import { pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import { type BasicStoreEntityDeadLetterMessage, ENTITY_TYPE_DEAD_LETTER_MESSAGE } from './deadLetterMessage-types';
import type { QueryDeadLetterMessagesArgs } from '../../generated/graphql';

export const findById = (context: AuthContext, user: AuthUser, deadLetterId: string) => {
  return storeLoadById(context, user, deadLetterId, ENTITY_TYPE_DEAD_LETTER_MESSAGE) as unknown as BasicStoreEntityDeadLetterMessage;
};

export const findDeadLetterPaginated = (context: AuthContext, user: AuthUser, opts: QueryDeadLetterMessagesArgs) => {
  return pageEntitiesConnection<BasicStoreEntityDeadLetterMessage>(context, user, [ENTITY_TYPE_DEAD_LETTER_MESSAGE], opts);
};
