import { WorkNotALiveError } from '../config/errors';
import { redisGetWork } from '../database/redis';
import { checkDraftInContext } from '../http/httpServer-draft';
import { isVerifiedFormSubmission } from '../modules/form/form-submission-context';
import { getEnterpriseEditionInfo, IS_LTS_PLATFORM } from '../modules/settings/licensing';
import type { BasicStoreSettings } from '../types/settings';
import type { AuthContext, AuthUser } from '../types/user';
import { isBypassUser, isUserInPlatformOrganization } from '../utils/access';
import { INTAKE_HEADERS } from './intake-context-headers';

// The rules that turn the headers of an ingestion write into its context. One set for both ways a
// write arrives: a worker's request over HTTP (httpAuthenticatedContext.js, httpGraphqlContext.ts)
// and the in-process intake of the worker-less POC (intake-context.ts), so that the same message
// writes under the same context whichever way it comes.

type IntakeHeaders = Record<string, string | string[] | undefined>;

// Before the user is known
export const applyIntakeHeaders = (context: AuthContext, headers: IntakeHeaders) => {
  const mutable = context as any;
  mutable.workId = headers[INTAKE_HEADERS.work]; // Api call comes from a worker processing
  mutable.draft_context = headers[INTAKE_HEADERS.draft]; // Api call is to be made is specific draft context
  mutable.eventId = headers[INTAKE_HEADERS.event]; // Api call is due to listening event
  mutable.previousStandard = headers[INTAKE_HEADERS.previousStandard]; // Previous standard id
};

// Once the user is authenticated: `user` as the authentication gives it (the applicant when a
// bypass user impersonates one), `contextUser` the user the context carries
export const applyIntakeUser = (context: AuthContext, headers: IntakeHeaders, user: AuthUser, contextUser: AuthUser, settings: BasicStoreSettings | undefined) => {
  const mutable = context as any;
  // No draft header: the user's own draft (an empty header means live)
  if (!Object.keys(headers).some((key) => key === INTAKE_HEADERS.draft)) {
    mutable.draft_context = user.draft_context;
  }
  // The origin of the context user is rebuilt, keep who really authenticated when an applicant is impersonated
  mutable.real_authentication_id = user.origin?.real_authentication_id;
  mutable.user = contextUser;
  // If full sync needs to be done : used only by bypass user (worker)
  mutable.synchronizedUpsert = user.origin?.synchronized_upsert === true || (headers[INTAKE_HEADERS.synchronized] === 'true' && isBypassUser(user));
  mutable.user_inside_platform_organization = isUserInPlatformOrganization(user, settings as any);
  const licenseInfo = getEnterpriseEditionInfo(settings as any);
  mutable.blocked_for_lts_validation = IS_LTS_PLATFORM && !licenseInfo.license_validated;
};

// What a write bound to a work or a draft must pass before it runs: a deleted work refuses every
// write (how a user cancels an ingestion), a live work may be the verified import of a form
// submission, a draft must still be open
export const checkIntakeContext = async (context: AuthContext) => {
  const mutable = context as any;
  if (context.workId) {
    // The work hash is read once for both checks: the same liveness rule as isWorkAlive, then the form submission binding
    const work = await redisGetWork(context.workId);
    if (work?.is_initialized !== 'true') {
      throw WorkNotALiveError();
    }
    // Import of a Form Intake submission: lets the applicant write with the form capability
    mutable.form_submission = isVerifiedFormSubmission(context, work);
  }
  await checkDraftInContext(context);
};
