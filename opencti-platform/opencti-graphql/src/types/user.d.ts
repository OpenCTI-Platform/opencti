import type Express from 'express';
import type { BasicStoreCommon, BasicStoreIdentifier, StoreMarkingDefinition } from './store';
import type { Group } from './group';
import type { ConfidenceLevel } from '../generated/graphql';
import type { TracingContext } from '../utils/access';
import type { BasicStoreEntityOrganization } from '../modules/organization/organization-types';

interface UserRole extends BasicStoreIdentifier {
  name: string;
}

interface UserCapability {
  name: string;
}

interface UserOrigin {
  socket: string;
  name?: string;
  user_id?: string;
  group_ids?: string[];
  organization_ids?: string[];
  applicant_id?: string;
  playbook_id?: string;
  referer?: string;
  synchronized_upsert?: boolean;
  user_metadata?: object;
  call_retry_number?: number;
  // Real credential owner id when authenticatedUser was swapped via opencti-applicant-id impersonation.
  real_authentication_id?: string;
}

interface UserApiToken {
  id: string;
  name: string;
  hash: string;
  created_at: string;
  expires_at: string | null;
  masked_token: string;
}

interface AuthUser extends BasicStoreIdentifier {
  entity_type: string;
  id: string;
  internal_id: string;
  individual_id: string | undefined;
  name: string;
  user_email: string;
  account_lock_after_date: Date | undefined;
  user_service_account?: boolean;
  origin: Partial<UserOrigin>;
  roles: Array<UserRole>;
  groups: Array<Group>;
  organizations: Array<BasicStoreCommon>;
  administrated_organizations: Array<BasicStoreEntityOrganization>;
  capabilities: Array<UserCapability>;
  capabilitiesInDraft?: Array<UserCapability>;
  allowed_marking: Array<StoreMarkingDefinition>;
  default_marking?: Array<{ entity_type: string; values: Array<StoreMarkingDefinition> }>;
  max_shareable_marking: Array<StoreMarkingDefinition>;
  api_tokens: Array<UserApiToken>;
  account_status: string;
  effective_confidence_level: ConfidenceLevel | null;
  restrict_delete: boolean | null;
  no_creators: boolean | null;
  user_confidence_level: ConfidenceLevel | null;
  personal_notifiers?: Array<string>;
  draft_context?: string | undefined;
  otp_activated?: boolean;
  password_valid_until?: Date | null;
  otp_secret?: string;
  creator_id?: string | string[];
  unsubscribed_news_feed_types?: string[];
}

interface AuthContext {
  otp_mandatory: boolean;
  source: string;
  tracing: TracingContext;
  user: AuthUser | undefined;
  draft_context?: string | undefined;
  workId?: string;
  form_submission?: boolean; // the request is the import of a verified Form Intake submission
  real_authentication_id?: string; // owner of the credential when the request impersonates an applicant (worker)
  batch?: Record<string, any>;
  changeDraftContext?: (draftId: string) => void;
  eventId?: string | undefined;
  user_inside_platform_organization: boolean;
  user_otp_validated?: boolean;
  user_with_session?: boolean;
  synchronizedUpsert?: boolean;
  previousStandard?: string;
  // POC ingestion sequencer (plan 0009 s9.8.3): in-bundle ref ids collected when the
  // ||M|| marks were stripped from this request's variables (httpAuthenticatedContext)
  memberRefIds?: Set<string>;
  // POC chunk-queue intake (retry-gap option 1): a creation whose hard reference is still
  // missing at apply time is RETAINED by the sequencer (pending intents) instead of rejected
  deferMissingRefs?: boolean;
  // POC chunk intake: called once by the sequencer boundary when this context's intent has
  // been accepted into the intake queue (end of the operation's pre-loop phase); the chunk
  // manager uses it to release its pre-loop admission permit.
  onIntentQueued?: () => void;
  req?: Express.Request;
  requestAbortSignal?: AbortSignal;
  blocked_for_lts_validation?: boolean;
  sequencer?: {
    scope: 'applying' | 'bypass';
    // s9.12.3: the running apply's strip sink, created by the loop (sequencer-strip-sink.ts)
    stripSink?: { targetRef: string; relType: string }[];
    // task 0040: the elements the running apply upserted without any change, by internal id, each
    // the diff basis it was compared with (no-op memo)
    noopSink?: Map<string, object>;
    // Stage C identity map, served through the context so engine.ts needs no sequencer import
    resolutions?: {
      serveBare: (context: AuthContext, user: AuthUser, ids: string[], opts: Record<string, unknown>)
      => Promise<{ hits: any[]; misses: string[] } | null>;
      serveWithRefs: (context: AuthContext, user: AuthUser, ids: string[], opts: Record<string, unknown>)
      => Promise<{ hits: any[]; misses: string[] } | null>;
      ingestBare: (elements: any[]) => void;
      // 2026-09-25: relation dedup shortcut for endpoints created by the running batch
      wasCreatedInBatch?: (internalId: string) => boolean;
      wasAbsentAtBatchStart?: (element: any) => boolean;
      // task 0040 defect 2: whether the batch holds a with-refs copy of an element (sequencer-multi-writer relationBasisContext)
      hasWithRefs?: (id: string) => boolean;
    };
  };
}
