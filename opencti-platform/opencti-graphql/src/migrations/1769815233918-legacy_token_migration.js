import { logApp } from '../config/conf';
import { fullEntitiesOrRelationsList } from '../database/middleware';
import { ENTITY_TYPE_USER } from '../schema/internalObject';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { generateTokenHmac } from '../modules/user/user-domain';
import { elUpdate } from '../database/engine';

const message = '[MIGRATION] Legacy Token Migration';

export const up = async (next) => {
  logApp.info(`${message} > started`);
  // Fetch all users
  const context = executionContext('migration');
  const users = await fullEntitiesOrRelationsList(context, SYSTEM_USER, [ENTITY_TYPE_USER]);
  logApp.info(`${message} > found ${users.length} users`);
  for (let i = 0; i < users.length; i += 1) {
    const user = users[i];
    // Check if user has legacy token
    if (user.api_token) {
      logApp.info(`${message} > Migrating user ${i}/${users.length}`);
      const legacyTokenHash = await generateTokenHmac(user.api_token);
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
        const source = "ctx._source.api_tokens = params.api_tokens; ctx._source.remove('api_token');";
        await elUpdate(user._index, user.internal_id, {
          script: { source, lang: 'painless', params: { api_tokens: newTokensList } },
        });
      } else {
        // Ensure old api_token attribute cleanup
        const source = "ctx._source.remove('api_token');";
        await elUpdate(user._index, user.internal_id, { script: { source, lang: 'painless' } });
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
