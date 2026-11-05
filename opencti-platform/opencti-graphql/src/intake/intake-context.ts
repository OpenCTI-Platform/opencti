import { getEntityFromCache } from '../database/cache';
import { computeLoaders } from '../http/httpAuthenticatedContext';
import { authenticateIntakeWriter, userWithOrigin } from '../modules/user/user-domain';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import type { BasicStoreSettings } from '../types/settings';
import type { AuthContext, AuthUser } from '../types/user';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { applyIntakeHeaders, applyIntakeUser, checkIntakeContext } from './intake-context-rules';
import { type IntakeEnvelope, intakeHeadersOf } from './intake-envelope';

// The context of an in-process ingestion write (worker-less intake, POC): what a worker's request
// gives the platform in headers, the push message gives in its envelope (intake-envelope.ts). The
// context is built from those headers by the rules the HTTP edge applies
// (intake-context-rules.ts), so a message writes under the context the worker would have given
// it. A retained write keeps its envelope and rebuilds the same context when it runs again.

// Throws as the HTTP edge refuses: an unknown writer or applicant, a synchronized upsert without
// the bypass capability, a deleted work (WorkNotALiveError), a draft no longer open
export const createIntakeContext = async (envelope: IntakeEnvelope, contextName: string) => {
  const context = executionContext(contextName) as any;
  const headers = intakeHeadersOf(envelope);
  const req = { headers, ip: 'intake', header: (name: string) => headers[name] };
  context.req = req;
  const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  context.otp_mandatory = (settings as any)?.otp_mandatory ?? false;
  applyIntakeHeaders(context, headers);
  const user = await authenticateIntakeWriter(context, req as any, envelope.user_id);
  applyIntakeUser(context, headers, user, userWithOrigin(req as any, user), settings);
  context.user_otp_validated = true;
  context.user_with_session = false;
  context.batch = computeLoaders(context, context.user);
  await checkIntakeContext(context);
  return { context: context as AuthContext, user: context.user as AuthUser };
};
