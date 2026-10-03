import { ENTITY_TYPE_BACKGROUND_TASK } from '../../schema/internalObject';
import { ENTITY_TYPE_CONTAINER_CASE_RFI } from '../case/case-rfi/case-rfi-types';
import { ENTITY_TYPE_CUSTOM_VIEW } from '../customView/customView-types';
import { ENTITY_TYPE_FORM } from '../form/form-types';
import { ENTITY_TYPE_PLAYBOOK } from '../playbook/playbook-types';
import { ENTITY_TYPE_PUBLIC_DASHBOARD } from '../publicDashboard/publicDashboard-types';
import { ENTITY_TYPE_WORKFLOW_DEFINITION } from '../workflow/types/workflow-types';
import { ENTITY_TYPE_WORKSPACE } from '../workspace/workspace-types';

/**
 * How the payload sits on the document, and — as a direct consequence — whether Elasticsearch
 * can pre-select the documents that hold the source id.
 *
 * - `json`: a serialized JSON field, declared `format: 'json'`, which maps to `text`. A phrase
 *   match on the id pre-selects.
 * - `base64`: a Base64 of a JSON, declared `format: 'short'`. The id never appears in clear in
 *   the indexed value, so nothing can pre-select and every document of the type is read.
 * - `object`: the platform stores the payload as an object rather than a string, under
 *   `format: 'flat'`, whose leaves are indexed as whole unanalyzed keywords. A phrase match on a
 *   substring can never hit, so here too every document of the type is read.
 * - `nested-json`: a serialized JSON field carried by a `nested` sub-document, which a top-level
 *   phrase match cannot reach.
 */
export type UserMergeBlobShape = 'json' | 'base64' | 'object' | 'nested-json';

/** A lifecycle state the merge precondition rules out, reported rather than orchestrated. */
export interface UserMergeBlobActivity {
  path: string;
  equals: string | boolean;
  negate?: boolean;
}

export interface UserMergeBlobTarget {
  /** Stable identifier, used in the report detail and in the journal. */
  id: string;
  registerRow: string;
  entityType: string;
  /**
   * Field holding the payload. For `nested-json`, the nested field itself: every one of its
   * sub-documents is walked, since the whole sub-document is read anyway.
   */
  path: string;
  shape: UserMergeBlobShape;
  /** Set when the same field answers for more than one register row. */
  alsoCovers?: string[];
  activity?: UserMergeBlobActivity;
}

/**
 * Every JSON payload the platform stores as an opaque blob and that can name a user.
 *
 * `History.context_data` is deliberately absent for the same reason it was left out of the
 * filter handler: its volume is of a different order, it is a frozen snapshot that is never
 * replayed, and the register groups it with the raw mutation input and the subject ids that
 * belong to a later chunk.
 */
export const USER_MERGE_BLOB_TARGETS: UserMergeBlobTarget[] = [
  {
    id: 'workspace-manifest',
    registerRow: 'workspace.manifest',
    entityType: ENTITY_TYPE_WORKSPACE,
    path: 'manifest',
    shape: 'base64',
  },
  {
    id: 'custom-view-manifest',
    registerRow: 'custom-view.manifest',
    entityType: ENTITY_TYPE_CUSTOM_VIEW,
    path: 'manifest',
    shape: 'base64',
  },
  {
    id: 'public-dashboard-private-manifest',
    registerRow: 'public-dashboard.manifests',
    entityType: ENTITY_TYPE_PUBLIC_DASHBOARD,
    path: 'private_manifest',
    shape: 'base64',
  },
  {
    // Same register row as the private manifest: one row covers both fields of the entity.
    id: 'public-dashboard-public-manifest',
    registerRow: 'public-dashboard.manifests',
    entityType: ENTITY_TYPE_PUBLIC_DASHBOARD,
    path: 'public_manifest',
    shape: 'base64',
  },
  {
    id: 'playbook-definition',
    registerRow: 'playbook.definition-nodes-configuration',
    entityType: ENTITY_TYPE_PLAYBOOK,
    path: 'playbook_definition',
    shape: 'json',
  },
  {
    id: 'form-schema',
    registerRow: 'form.schema-defaults',
    entityType: ENTITY_TYPE_FORM,
    path: 'form_schema',
    shape: 'json',
  },
  {
    id: 'workflow-definition-published-version',
    registerRow: 'workflow-definition.versions-content',
    entityType: ENTITY_TYPE_WORKFLOW_DEFINITION,
    path: 'published_version',
    shape: 'nested-json',
  },
  {
    id: 'workflow-definition-draft-version',
    registerRow: 'workflow-definition.versions-content',
    entityType: ENTITY_TYPE_WORKFLOW_DEFINITION,
    path: 'draft_version',
    shape: 'nested-json',
  },
  {
    id: 'workflow-definition-all-versions',
    registerRow: 'workflow-definition.versions-content',
    entityType: ENTITY_TYPE_WORKFLOW_DEFINITION,
    path: 'all_versions',
    shape: 'nested-json',
  },
  {
    id: 'background-task-actions',
    registerRow: 'background-task.actions-context-values',
    entityType: ENTITY_TYPE_BACKGROUND_TASK,
    path: 'actions',
    shape: 'object',
    activity: { path: 'completed', equals: true, negate: true },
  },
  {
    // The register splits the row on the state of the request, not on where it is stored: both
    // rows read and write the same field, so one target answers for the two.
    id: 'case-rfi-request-access',
    registerRow: 'case-rfi-active.request-access-applicant-id',
    alsoCovers: ['case-rfi-terminal.request-access-applicant-id'],
    entityType: ENTITY_TYPE_CONTAINER_CASE_RFI,
    path: 'x_opencti_request_access',
    shape: 'json',
  },
];

/**
 * The draft patch, which is not a target of its own: `draft_updates_patch` is a global attribute
 * carried by every draftable entity, so it is not qualified by an entity type the way the other
 * targets are.
 *
 * A draft is work in progress that stopping the workers does not drain. Validating one after the
 * merge replays its patch against live data, which would re-inject the source id — so the patch
 * is rewritten with the rest, `initial_value` included: that field is what undoing the draft
 * restores, and leaving it behind would re-inject the source id on a rollback.
 */
export const USER_MERGE_DRAFT_PATCH_TARGET = {
  id: 'draft-updates-patch',
  registerRow: 'draftable.draft-updates-patch',
  path: 'draft_change.draft_updates_patch',
};

export const userMergeBlobCoveredRows = (): string[] => {
  const rows = USER_MERGE_BLOB_TARGETS.flatMap((target) => [target.registerRow, ...(target.alsoCovers ?? [])]);
  return Array.from(new Set([...rows, USER_MERGE_DRAFT_PATCH_TARGET.registerRow]));
};

/** Paths qualified by entity type, as the disjointness check compares them literally. */
export const userMergeBlobFieldPaths = (): string[] => {
  const paths = USER_MERGE_BLOB_TARGETS.map((target) => `${target.entityType}.${target.path}`);
  return Array.from(new Set([...paths, USER_MERGE_DRAFT_PATCH_TARGET.path]));
};
