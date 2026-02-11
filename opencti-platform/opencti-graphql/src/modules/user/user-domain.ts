import { v4 as uuid } from 'uuid';
import { DateTime } from 'luxon';
import * as crypto from 'crypto';
import type { AuthContext, AuthUser } from '../../types/user';
import { addUser, findUserPaginated } from '../../domain/user';
import { SYSTEM_USER } from '../../utils/access';
import type { BasicGroupEntity } from '../../types/store';
import { findDefaultIngestionGroups } from '../../domain/group';
import { FunctionalError, ValidationError } from '../../config/errors';
import { TokenDuration, type UserAddInput, type UserTokenAddInput } from '../../generated/graphql';
import { getEntityFromCache } from '../../database/cache';
import type { BasicStoreSettings } from '../../types/settings';
import { ENTITY_TYPE_SETTINGS, ENTITY_TYPE_USER } from '../../schema/internalObject';
import { updateAttribute } from '../../database/middleware';

import { publishUserAction } from '../../listener/UserActionListener';
import { notify } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { internalLoadById } from '../../database/middleware-loader';
import { UPDATE_OPERATION_ADD, UPDATE_OPERATION_REMOVE } from '../../database/utils';
import { apiTokens } from '../attributes/internalObject-registrationAttributes';
import { getPlatformCrypto } from '../../utils/platformCrypto';
import { memoize } from '../../utils/memoize';

// -- Existing Logic --
export const userAlreadyExists = async (context: AuthContext, name: string) => {
  // We use SYSTEM_USER because manage ingestion should be enough to create an ingestion Feed
  const users = await findUserPaginated(context, SYSTEM_USER, {
    first: 1,
    filters: {
      mode: 'and',
      filters: [
        {
          key: ['name'],
          values: [name],
        },
      ],
      filterGroups: [],
    },
  });
  return users.edges.length > 0;
};

type OnTheFlyInput = { userName: string; serviceAccount: boolean; confidenceLevel: number | null | undefined };
export const createOnTheFlyUser = async (context: AuthContext, user: AuthUser, input: OnTheFlyInput) => {
  const defaultIngestionGroups: BasicGroupEntity[] = await findDefaultIngestionGroups(context, user) as BasicGroupEntity[];
  if (defaultIngestionGroups.length < 1) {
    throw FunctionalError('You have not defined a default group for ingestion users', {});
  }
  const isUserAlreadyExisting = await userAlreadyExists(context, input.userName);
  if (isUserAlreadyExisting) {
    if (input.serviceAccount) {
      throw FunctionalError('This service account already exists. Change the instance name to change the automatically created service account name', { name: input.userName });
    }
    throw FunctionalError('This user already exists. Change the feed\'s name to change the automatically created user\'s name', { name: input.userName });
  }
  const { platform_organization } = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);

  let userInput: UserAddInput = {
    password: uuid(),
    user_email: `automatic+${uuid()}@opencti.invalid`,
    name: input.userName,
    prevent_default_groups: true,
    groups: [defaultIngestionGroups[0].id],
    objectOrganization: platform_organization && !input.serviceAccount ? [platform_organization] : [],
    user_service_account: input.serviceAccount,
  };

  if (input.confidenceLevel) {
    const userConfidence = input.confidenceLevel;
    if (userConfidence < 0 || userConfidence > 100 || !Number.isInteger(userConfidence)) {
      throw ValidationError('The confidence_level should be an integer between 0 and 100', 'confidence_level');
    }
    userInput = { ...userInput, user_confidence_level: { max_confidence: userConfidence, overrides: [] } };
  }
  return await addUser(context, user, userInput);
};

// -- API Token Logic --
export interface GeneratedToken {
  token: string;
  hash: string;
  masked_token: string;
}

// Add token
const addToken = async (context: AuthContext, user: AuthUser, userId: string, input: UserTokenAddInput) => {
  const { duration, name } = input;
  let expires_at = null;
  if (duration && duration !== TokenDuration.Unlimited) {
    const durationDays: Record<string, number> = {
      [TokenDuration.Days_30]: 30,
      [TokenDuration.Days_60]: 60,
      [TokenDuration.Days_90]: 90,
      [TokenDuration.Days_365]: 365,
    };
    const days = durationDays[duration];
    if (days) {
      expires_at = DateTime.now().plus({ days }).toUTC().toString();
    }
  }
  const generatedToken = await generateSecureToken();
  const { token, hash, masked_token } = generatedToken;
  const tokenId = uuid();
  const now = DateTime.now().toUTC().toString();
  const newToken = {
    id: tokenId,
    name,
    hash,
    created_at: now,
    expires_at,
    masked_token,
  };
  const updates = [{ key: apiTokens.name, value: [newToken], operation: UPDATE_OPERATION_ADD }];
  const { element } = await updateAttribute(context, user, userId, ENTITY_TYPE_USER, updates);
  return { token: newToken, token_value: token, element };
};
export const addUserToken = async (context: AuthContext, user: AuthUser, userId: string, input: UserTokenAddInput) => {
  const { token, token_value, element } = await addToken(context, user, userId, input);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `generated a new API token '${token.name}'`,
    context_data: {
      id: user.id,
      entity_type: ENTITY_TYPE_USER,
      input: {
        duration: input.duration,
        name: input.name,
        token_id: token.id,
      },
    },
  });
  // Notify for cache invalidation
  await notify(BUS_TOPICS[ENTITY_TYPE_USER].EDIT_TOPIC, element, user);
  return {
    token_id: token.id,
    plaintext_token: token_value,
    masked_token: token.masked_token,
    expires_at: token.expires_at,
  };
};
export const addUserTokenByAdmin = async (context: AuthContext, user: AuthUser, userId: string, input: UserTokenAddInput) => {
  // Load target user
  const userToEdit = await internalLoadById(context, user, userId) as unknown as AuthUser;
  if (!userToEdit) {
    throw FunctionalError('User not found', { userId });
  }
  const { token, token_value, element } = await addToken(context, user, userId, input);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `generated a new API token '${token.name}' for user '${userToEdit.user_email}'`,
    context_data: {
      id: userId,
      entity_type: ENTITY_TYPE_USER,
      input: {
        duration: input.duration,
        name: input.name,
        token_id: token.id,
      },
    },
  });
  // Notify for cache invalidation
  await notify(BUS_TOPICS[ENTITY_TYPE_USER].EDIT_TOPIC, element, user);
  return {
    token_id: token.id,
    plaintext_token: token_value,
    masked_token: token.masked_token,
    expires_at: token.expires_at,
  };
};

// Revoke token
const revokeToken = async (context: AuthContext, user: AuthUser, targetUserId: string, tokenId: string) => {
  // Load target user
  const userToEdit = await internalLoadById(context, user, targetUserId) as unknown as AuthUser;
  if (!userToEdit) {
    throw FunctionalError('User not found', { targetUserId });
  }
  const tokens = userToEdit.api_tokens || [];
  const tokenToRemove = tokens.find((t: any) => t.id === tokenId);
  if (!tokenToRemove) {
    throw FunctionalError('Token not found', { tokenId });
  }
  const updates = [{ key: apiTokens.name, value: [tokenToRemove], operation: UPDATE_OPERATION_REMOVE }];
  const { element } = await updateAttribute(context, user, targetUserId, ENTITY_TYPE_USER, updates);
  return { element, token: tokenToRemove, user: userToEdit };
};
export const revokeUserToken = async (context: AuthContext, user: AuthUser, tokenId: string) => {
  const { element, token } = await revokeToken(context, user, user.id, tokenId);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `revoked API token '${token.name}'`,
    context_data: {
      id: user.id,
      entity_type: ENTITY_TYPE_USER,
      input: {
        token_id: tokenId,
      },
    },
  });
  // Notify for cache invalidation
  await notify(BUS_TOPICS[ENTITY_TYPE_USER].EDIT_TOPIC, element, user);
  return tokenId;
};
export const revokeUserTokenByAdmin = async (context: AuthContext, user: AuthUser, targetUserId: string, tokenId: string) => {
  const { element, token, user: targetUser } = await revokeToken(context, user, targetUserId, tokenId);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `revoked API token '${token.name}' for user '${targetUser.user_email}'`,
    context_data: {
      id: targetUserId,
      entity_type: ENTITY_TYPE_USER,
      input: {
        token_id: tokenId,
      },
    },
  });
  // Notify for cache invalidation
  await notify(BUS_TOPICS[ENTITY_TYPE_USER].EDIT_TOPIC, element, user);
  return tokenId;
};

/**
 * Generate a secure random token.
 * 48 bytes = 384 bits of entropy.
 * Returns the plain token (to be shown once), the hash (to be stored), and a masked version.
 */
export const generateSecureToken = async (): Promise<GeneratedToken> => {
  // 48 bytes -> base64 -> 64 chars
  const random = crypto.randomBytes(48).toString('base64url');
  const token = `flgrn_octi_tkn_${random}`;
  const hash = await generateTokenHmac(token);
  const masked_token = `****${token.slice(-4)}`;
  return { token, hash, masked_token };
};

/**
 * Hash a token using hmac algorithm.
 * @param token the token to hash
 */
const hmacDerivation = memoize(async () => {
  const factory = await getPlatformCrypto();
  return factory.deriveHmac(['authentication', 'token'], 1);
});

export const generateTokenHmac = async (token: string): Promise<string> => {
  const { hmac } = await hmacDerivation();
  return hmac(Buffer.from(token));
};
