/**
 * The exhaustive register of user references in the platform.
 *
 * This list is the questions; the handlers are the answers. It describes the existing
 * codebase — every place a user id is stored — and it does not grow chunk by chunk. What
 * grows is the set of rows claimed by a handler.
 *
 * It lives in code, and not only in the specification, because the engine cannot name what
 * no handler covers unless it holds the full list independently of the handlers. Without
 * it, a report can only show what is done and never what is missing: the blind spots go
 * invisible exactly when they are most numerous.
 *
 * Only what the engine needs at runtime is transcribed here — id, disposition, label, path.
 * The per-row analysis stays in the specification, which is the record of the reasoning that
 * produced the list, not a document to keep in sync at runtime.
 */

export const USER_MERGE_REGISTER_VERSION = 'v4';

export enum UserMergeDisposition {
  /** The reference must be re-pointed from the source to the target. */
  Transfer = 'transfer',
  /** The reference must be dropped or reset; carrying it over would be wrong. */
  Invalidate = 'invalidate',
  /** Whether to transfer depends on the state of the carrying object. */
  Conditional = 'conditional',
  /** The reference is deliberately left as is. */
  Retain = 'retain',
  /** Outside the reach of a database merge (in-flight queue messages, opaque state). */
  OutOfScope = 'out-of-scope',
}

export interface UserMergeRegisterRow {
  /** Stable identifier a handler declares coverage against. Never reused, never renumbered. */
  id: string;
  disposition: UserMergeDisposition;
  /** Human-readable name of the entity or store the reference lives on. */
  label: string;
  /** Field path carrying the user id. */
  path: string;
}

const row = (id: string, disposition: UserMergeDisposition, label: string, path: string): UserMergeRegisterRow => ({ id, disposition, label, path });

const TRANSFER = UserMergeDisposition.Transfer;
const INVALIDATE = UserMergeDisposition.Invalidate;
const CONDITIONAL = UserMergeDisposition.Conditional;
const RETAIN = UserMergeDisposition.Retain;
const OUT_OF_SCOPE = UserMergeDisposition.OutOfScope;

export const USER_MERGE_REGISTER: UserMergeRegisterRow[] = [
  // --- transfer (40) ---------------------------------------------------------------------
  row('activity.user-id', TRANSFER, 'Activity', 'user_id'),
  row('activity-history-pir-history.applicant-id', TRANSFER, 'Activity / History / PirHistory', 'applicant_id'),
  row('background-task-terminal.initiator-id', TRANSFER, 'BackgroundTask (done/failed/cancelled)', 'initiator_id'),
  row('basic-object.creator-id', TRANSFER, 'BasicObject / BasicRelationship', 'creator_id[]'),
  row('basic-object.i-attributes-user-id', TRANSFER, 'BasicObject / BasicRelationship', 'i_attributes[].user_id'),
  row('case-rfi-active.request-access-applicant-id', TRANSFER, 'Case-Rfi (active request)', 'x_opencti_request_access[].applicant_id'),
  row('case-rfi-terminal.request-access-applicant-id', TRANSFER, 'Case-Rfi (terminal request)', 'x_opencti_request_access (serialized JSON) -> applicant_id'),
  row('custom-view.manifest', TRANSFER, 'CustomView', 'manifest (Base64)'),
  row('deleted-objects.all-references', TRANSFER, 'Deleted objects', 'creator_id / i_attributes.user_id / restricted_members / connections / serialized fields'),
  row('feed.filters', TRANSFER, 'Feed', 'filters'),
  row('fintel-template.instance-filters', TRANSFER, 'FintelTemplate', 'instance_filters'),
  row('form.schema-defaults', TRANSFER, 'Form', 'form_schema.draftDefaults / fields[].defaultValue'),
  row('history.context-data-attribution', TRANSFER, 'History', 'context_data.creator_ids[]'),
  row('history.context-data-payload', TRANSFER, 'History', 'context_data.input / list_params / filters / history_changes / subject ids'),
  row('history.user-id', TRANSFER, 'History', 'user_id'),
  row('ingestion.user-id', TRANSFER, 'IngestionCsv / IngestionJson / IngestionRss / IngestionTaxii / IngestionTaxiiCollection', 'user_id'),
  row('internal-file.metadata-creator-id', TRANSFER, 'InternalFile', 'metaData.creator_id'),
  row('news-feed-item.user-id', TRANSFER, 'NewsFeedItem', 'user_id'),
  row('notification-terminal.user-id', TRANSFER, 'Notification (read or terminal)', 'user_id'),
  row('object-assignee.connections', TRANSFER, 'object-assignee', 'rel_object-assignee.internal_id / connections[].internal_id'),
  row('object-participant.connections', TRANSFER, 'object-participant', 'rel_object-participant.internal_id / connections[].internal_id'),
  row('authorized-members.restricted-members', TRANSFER, 'Objects supporting Authorized Members', 'restricted_members[].id'),
  row('pir.pir-filters', TRANSFER, 'Pir', 'pir_filters'),
  row('pir.criteria-filters', TRANSFER, 'Pir', 'pir_criteria[].filters'),
  row('pir-history.user-id', TRANSFER, 'PirHistory', 'user_id'),
  row('playbook.definition-nodes-configuration', TRANSFER, 'Playbook', 'playbook_definition.nodes[].configuration'),
  row('public-dashboard.user-id', TRANSFER, 'PublicDashboard', 'user_id'),
  row('public-dashboard.manifests', TRANSFER, 'PublicDashboard', 'private_manifest / public_manifest (Base64)'),
  row('settings.xtm-hub-registration-user-id', TRANSFER, 'Settings', 'xtm_hub_registration_user_id'),
  row('stream-collection.filters', TRANSFER, 'StreamCollection', 'filters'),
  row('stream-collection.origin-filters', TRANSFER, 'StreamCollection', 'origin_filters'),
  row('sync.user-id', TRANSFER, 'Sync', 'user_id'),
  row('taxii-collection.filters', TRANSFER, 'TaxiiCollection', 'filters'),
  row('trigger.recipients', TRANSFER, 'Trigger', 'recipients[]'),
  row('trigger.filters', TRANSFER, 'Trigger', 'filters'),
  row('work-terminal.user-id', TRANSFER, 'Work (finished)', 'user_id'),
  row('workflow-definition.versions-content', TRANSFER, 'WorkflowDefinition', 'published_version.content / draft_version.content / all_versions[].content'),
  row('workflow-definition.versions-created-by', TRANSFER, 'WorkflowDefinition', 'published_version.createdBy / draft_version.createdBy / all_versions[].createdBy'),
  row('workflow-instance.history-user-id', TRANSFER, 'WorkflowInstance', 'history[].user_id'),
  row('workspace.manifest', TRANSFER, 'Workspace', 'manifest (Base64)'),

  // --- invalidate (22) -------------------------------------------------------------------
  row('accesses-to.connections', INVALIDATE, 'accesses-to', 'connections[].internal_id (source user)'),
  row('api-token.usage-key', INVALIDATE, 'API token', '{token_usage}:{tokenId}'),
  row('auth-user.cache-entries', INVALIDATE, 'AuthUser / Settings / access cache', 'entries keyed by user ID or containing memberships'),
  row('client-connection.auth-context', INVALIDATE, 'Client connection', 'connection auth context / subscriptions'),
  row('edit-context.keys', INVALIDATE, 'Edit context', 'edit:{instanceId}:{userId} / context:user:{userId} / context:instance:{instanceId}'),
  row('has-capability.connections', INVALIDATE, 'has-capability', 'connections[].internal_id (source user)'),
  row('has-capability-in-draft.connections', INVALIDATE, 'has-capability-in-draft', 'connections[].internal_id (source user)'),
  row('has-role.connections', INVALIDATE, 'has-role', 'connections[].internal_id (source user)'),
  row('member-of.connections', INVALIDATE, 'member-of', 'connections[].internal_id (source user)'),
  row('organization.authorized-authorities', INVALIDATE, 'Organization', 'authorized_authorities[]'),
  row('participate-to.connections', INVALIDATE, 'participate-to', 'connections[].internal_id (source user)'),
  row('password-reset.keys', INVALIDATE, 'Password reset', 'forgot_password_otp_{transactionId} / forgot_password_transactionId_{email}'),
  row('session.key', INVALIDATE, 'User session', 'sess:{sessionId}'),
  row('session.platform-sessions', INVALIDATE, 'User session', 'platform_sessions'),
  row('settings.ip-whitelist-exclusion-ids', INVALIDATE, 'Settings', 'platform_ip_whitelist_exclusion_ids[]'),
  row('settings.activity-listeners-ids', INVALIDATE, 'Settings', 'activity_listeners_ids[]'),
  row('sso.session-and-refresh-token', INVALIDATE, 'SSO session / refresh token', 'external subject, session, refresh token'),
  row('user.password', INVALIDATE, 'User', 'password / password_valid_until'),
  row('user.administration-fields', INVALIDATE, 'User', 'administrated_organizations / user_confidence_level / user_service_account'),
  row('user.account-status', INVALIDATE, 'User', 'account_status / account_lock_after_date'),
  row('user.otp', INVALIDATE, 'User', 'otp_secret / otp_qr / otp_activated'),
  row('user.api-tokens', INVALIDATE, 'User', 'api_tokens[]'),

  // --- conditional (21) ------------------------------------------------------------------
  row('background-task.actions-context-values', CONDITIONAL, 'BackgroundTask', 'actions[].context.values'),
  row('background-task.task-filters', CONDITIONAL, 'BackgroundTask', 'task_filters'),
  row('background-task-pending.initiator-id', CONDITIONAL, 'BackgroundTask (queued/running)', 'initiator_id'),
  row('connector.trigger-filters', CONDITIONAL, 'Connector', 'connector_trigger_filters'),
  row('connector.user-id', CONDITIONAL, 'Connector', 'connector_user_id'),
  row('decay-exclusion-rule.filters', CONDITIONAL, 'DecayExclusionRule', 'decay_exclusion_filters'),
  row('decay-rule.filters', CONDITIONAL, 'DecayRule', 'decay_filters'),
  row('feed.public-user-id', CONDITIONAL, 'Feed', 'feed_public_user_id'),
  row('inferred.derived-references', CONDITIONAL, 'Inferred relationships / inferred objects', 'creator_id / connections / derived references'),
  row('notification-unread.user-id', CONDITIONAL, 'Notification (unread)', 'user_id'),
  row('notification.subscription-topics', CONDITIONAL, 'Notification / activity subscription', 'topics and payloads containing user ID'),
  row('retention-rule.filters', CONDITIONAL, 'RetentionRule', 'filters'),
  row('saved-filter.filters', CONDITIONAL, 'SavedFilter', 'filters'),
  row('stream-collection.public-user-id', CONDITIONAL, 'StreamCollection', 'stream_public_user_id'),
  row('taxii-collection.public-user-id', CONDITIONAL, 'TaxiiCollection', 'taxii_public_user_id'),
  row('any-type.unregistered-serialized-field', CONDITIONAL, 'Any type', 'unregistered JSON/Base64 field containing exactly the source UUID'),
  row('draftable.draft-updates-patch', CONDITIONAL, 'Any draftable type', 'draft_updates_patch.*.(replaced_value|added_value|removed_value|initial_value)'),
  row('user.email-and-sso-identifier', CONDITIONAL, 'User', 'user_email / SSO identifier'),
  row('work-active.user-id', CONDITIONAL, 'Work (active)', 'user_id'),
  row('workflow-instance-pending.transition-actions', CONDITIONAL, 'WorkflowInstance (pending transition)', 'pendingTransition.actions[] / params'),
  row('workflow-instance-pending.transition-triggered-by', CONDITIONAL, 'WorkflowInstance (pending transition)', 'pendingTransition.triggeredBy'),

  // --- retain (10) -----------------------------------------------------------------------
  row('live-event.origin-user-id', RETAIN, 'Activity / Notification / Live event', 'event.origin.user_id and stream payloads'),
  row('application-log.structured-fields', RETAIN, 'Application log / audit export', 'structured fields user_id / source_user_id / target_user_id'),
  row('file-content.object-bytes', RETAIN, 'File content', 'object bytes'),
  row('file-metadata.object-metadata-path', RETAIN, 'File metadata', 'object metadata / path'),
  row('internal-file.list-filters', RETAIN, 'InternalFile', 'list_filters / metaData.list_filters'),
  row('playbook-execution.keys', RETAIN, 'Playbook execution', 'playbook_execution_{executionId} / playbook_executions_{playbookId}'),
  row('user.identity-fields', RETAIN, 'User', 'user_email / name / firstname / lastname / external / account_status'),
  row('user.ui-preferences', RETAIN, 'User', 'theme / language / bookmarks / default_dashboard / default_time_field / unit_system / UI preferences'),
  row('user.personal-notifiers', RETAIN, 'User', 'personal_notifiers'),
  row('user-account.user-id', RETAIN, 'User-Account', 'user_id'),

  // --- out-of-scope (6) ------------------------------------------------------------------
  row('background-task-queue.message', OUT_OF_SCOPE, 'Background task queue message', 'background-task queues: initiator / actions context'),
  row('connector.state', OUT_OF_SCOPE, 'Connector', 'connector_state'),
  row('connector-manager.contract-configuration', OUT_OF_SCOPE, 'Connector / ConnectorManager', 'manager_contract_configuration'),
  row('connector-queue.message', OUT_OF_SCOPE, 'Connector queue message', 'listen/push queues: message.user_id / connector_user_id / auth context'),
  row('notifier.configuration', OUT_OF_SCOPE, 'Notifier', 'notifier_configuration'),
  row('worker-queue.message', OUT_OF_SCOPE, 'Worker queue message', 'worker queues: message.user_id / auth context'),
];

const REGISTER_BY_ID = new Map(USER_MERGE_REGISTER.map((entry) => [entry.id, entry]));

export const findRegisterRow = (id: string): UserMergeRegisterRow | undefined => REGISTER_BY_ID.get(id);

export const registerRowsByDisposition = (disposition: UserMergeDisposition): UserMergeRegisterRow[] => {
  return USER_MERGE_REGISTER.filter((entry) => entry.disposition === disposition);
};
