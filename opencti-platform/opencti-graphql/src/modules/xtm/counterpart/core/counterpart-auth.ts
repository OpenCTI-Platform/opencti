import { issueXtmJwt } from '../../../../domain/xtm-auth';
import type { CounterpartCaller } from './counterpart-errors';

/**
 * The Authorization header of a counterpart lookup: a short-lived JWT signed by this platform for
 * the calling user, addressed to the product (same token as the XTM One pivot). The product
 * verifies it against this platform's JWKS and applies that user's own rights: link only for a
 * user without rights there, the facts for a user with rights. The product's service token is
 * never used to read facts on behalf of a user.
 */
export const counterpartAuthorization = async (caller: CounterpartCaller, productUrl: string): Promise<string> => {
  const token = await issueXtmJwt(caller, productUrl);
  return `Bearer ${token}`;
};
