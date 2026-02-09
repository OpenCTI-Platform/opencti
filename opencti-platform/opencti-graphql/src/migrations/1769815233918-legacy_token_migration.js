import { logApp } from '../config/conf';
import { fullEntitiesOrRelationsList, patchAttribute } from '../database/middleware';
import { ENTITY_TYPE_USER } from '../schema/internalObject';
import { SYSTEM_USER } from '../utils/access';
import { generateTokenHmac } from '../modules/user/user-domain';

const message = '[MIGRATION] Legacy Token Migration';

export const up = async (next) => {
  logApp.info(`${message} > started`);
  const context = { user: SYSTEM_USER };
  // Fetch all users
  const users = await fullEntitiesOrRelationsList(context, SYSTEM_USER, [ENTITY_TYPE_USER]);
  logApp.info(`${message} > found ${users.length} users`);
  for (let i = 0; i < users.length; i += 1) {
    const user = users[i];
    // Check if user has legacy token
    if (user.api_token) {
      logApp.info(`${message} > Migrating user ${i}/${users.length}`);
      const legacyTokenHash = generateTokenHmac(user.api_token);
      const currentTokens = user.api_tokens || [];
      // Check idempotency: if hash already exists in api_tokens
      const alreadyExists = currentTokens.some((t) => t.hash === legacyTokenHash);
      if (!alreadyExists) {
        const newToken = {
          id: 'base_token_' + user.internal_id,
          name: 'Legacy Token',
          hash: legacyTokenHash,
          created_at: new Date().toISOString(),
          masked_token: `****${user.api_token.slice(-4)}`,
          // Legacy tokens do not expire by default, or we could set a policy.
          // Acceptance Criteria says "ensure backward compatibility", so null (no expiration) is safest.
          expires_at: null,
        };
        const newTokensList = [...currentTokens, newToken];
        await patchAttribute(context, SYSTEM_USER, user.id, ENTITY_TYPE_USER, {
          api_token: null,
          api_tokens: newTokensList,
        });
      }
    }
  }
  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  // We generally don't rollback data enrichment like this in down migrations easily
  // without tracking which specific token ID was created.
  // For now, no-op or simple log.
  logApp.info(`${message} > down (skipped)`);
  next();
};
