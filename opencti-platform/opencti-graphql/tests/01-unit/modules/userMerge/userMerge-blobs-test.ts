import { describe, expect, it } from 'vitest';
import { toBase64 } from '../../../../src/database/utils';
import {
  USER_MERGE_BLOB_TARGETS,
  USER_MERGE_DRAFT_PATCH_TARGET,
  type UserMergeBlobTarget,
  userMergeBlobCoveredRows,
  userMergeBlobFieldPaths,
} from '../../../../src/modules/userMerge/userMerge-blobTargets';
import { USER_MERGE_REGISTER } from '../../../../src/modules/userMerge/userMerge-register';
import { rewriteJson, rewriteTarget } from '../../../../src/modules/userMerge/userMerge-blobsHandler';
import type { UserMergeRewriteCandidate } from '../../../../src/modules/userMerge/userMerge-bulk';

const SOURCE = 'aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa';
const TARGET = 'bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb';
const OTHER = 'cccccccc-3333-4333-8333-cccccccccccc';

const targetOf = (id: string): UserMergeBlobTarget => USER_MERGE_BLOB_TARGETS.find((entry) => entry.id === id)!;

const candidateOf = (source: Record<string, unknown>): UserMergeRewriteCandidate => ({
  id: 'candidate',
  index: 'opencti_internal_objects',
  source,
});

const rewriteOf = (targetId: string, source: Record<string, unknown>) => {
  return rewriteTarget(candidateOf(source), targetOf(targetId), SOURCE, TARGET);
};

const manifestOf = (creator: string) => toBase64(JSON.stringify({
  widgets: { w1: { dataSelection: [{ filters: { mode: 'and', filters: [{ key: ['creator_id'], values: [creator] }] } }] } },
}))!;

describe('userMerge blob targets', () => {
  it('should name register rows that exist', () => {
    const known = USER_MERGE_REGISTER.map((row) => row.id);
    userMergeBlobCoveredRows().forEach((rowId) => expect(known).toContain(rowId));
  });

  it('should claim ten rows, the two case-rfi ones through a single field', () => {
    expect(userMergeBlobCoveredRows()).toHaveLength(10);
    expect(userMergeBlobCoveredRows()).toContain('case-rfi-terminal.request-access-applicant-id');
  });

  // Two entity types can hold a field of the same name, and the disjointness check compares
  // the declared paths literally.
  it('should qualify the written entity paths by entity type', () => {
    userMergeBlobFieldPaths()
      .filter((path) => path !== USER_MERGE_DRAFT_PATCH_TARGET.path)
      .forEach((path) => expect(path).toContain('.'));
    expect(userMergeBlobFieldPaths()).toContain('Workspace.manifest');
  });

  // The scalar handler answers for `createdBy` on a register row of its own; claiming the whole
  // sub-document here would have the two handlers write the same field.
  it('should not claim the workflow version sub-document as a whole', () => {
    expect(userMergeBlobCoveredRows()).not.toContain('workflow-definition.versions-created-by');
  });
});

describe('userMerge Base64 manifests', () => {
  it('should decode, remap and re-encode a manifest', () => {
    const rewrite = rewriteOf('workspace-manifest', { manifest: manifestOf(SOURCE) });
    expect(rewrite).toHaveProperty('doc');
    expect((rewrite as { doc: Record<string, string> }).doc.manifest).toEqual(manifestOf(TARGET));
  });

  it('should leave a manifest naming nobody relevant untouched', () => {
    expect(rewriteOf('workspace-manifest', { manifest: manifestOf(OTHER) })).toBeUndefined();
  });

  // Only a payload that holds the source id and cannot be read is worth reporting: a manifest
  // broken for unrelated reasons is not this merge's business.
  it('should report a manifest holding the source id that it cannot decode', () => {
    expect(rewriteOf('workspace-manifest', { manifest: toBase64(`{ not json ${SOURCE}`)! })).toEqual('unparsable');
  });

  it('should stay silent on a broken manifest that names nobody relevant', () => {
    expect(rewriteOf('workspace-manifest', { manifest: toBase64('{ not json')! })).toBeUndefined();
  });

  it('should be a no-op on a second run', () => {
    const once = rewriteOf('workspace-manifest', { manifest: manifestOf(SOURCE) }) as { doc: Record<string, string> };
    expect(rewriteOf('workspace-manifest', { manifest: once.doc.manifest })).toBeUndefined();
  });
});

describe('userMerge object payloads', () => {
  it('should remap a background task action context without a parse step', () => {
    const actions = [{ type: 'ADD', context: { field: 'objectAssignee', values: [SOURCE, OTHER] } }];
    const rewrite = rewriteOf('background-task-actions', { actions }) as { doc: Record<string, any> };
    expect(rewrite.doc.actions[0].context.values).toEqual([TARGET, OTHER]);
  });

  it('should collapse the target id an action already named', () => {
    const actions = [{ type: 'ADD', context: { values: [SOURCE, TARGET] } }];
    const rewrite = rewriteOf('background-task-actions', { actions }) as { doc: Record<string, any> };
    expect(rewrite.doc.actions[0].context.values).toEqual([TARGET]);
  });
});

describe('userMerge nested workflow versions', () => {
  const versionOf = (creator: string, author: string) => ({
    id: 'v1',
    createdBy: author,
    content: JSON.stringify({ steps: [{ assignee: creator }] }),
  });

  it('should rewrite the version content', () => {
    const rewrite = rewriteOf('workflow-definition-published-version', {
      published_version: versionOf(SOURCE, OTHER),
    }) as { doc: Record<string, any> };
    expect(JSON.parse(rewrite.doc.published_version.content).steps[0].assignee).toEqual(TARGET);
  });

  // `createdBy` belongs to the scalar handler. Rewriting it here would write it twice.
  it('should leave the sibling createdBy to the scalar handler', () => {
    const rewrite = rewriteOf('workflow-definition-published-version', {
      published_version: versionOf(SOURCE, SOURCE),
    }) as { doc: Record<string, any> };
    expect(rewrite.doc.published_version.createdBy).toEqual(SOURCE);
  });

  it('should not rewrite a version whose content names nobody, even when createdBy is the source', () => {
    expect(rewriteOf('workflow-definition-draft-version', { draft_version: versionOf(OTHER, SOURCE) })).toBeUndefined();
  });

  it('should rewrite every version of the history and keep the ones it did not touch', () => {
    const all_versions = [versionOf(SOURCE, OTHER), versionOf(OTHER, OTHER)];
    const rewrite = rewriteOf('workflow-definition-all-versions', { all_versions }) as { doc: Record<string, any> };
    expect(rewrite.doc.all_versions).toHaveLength(2);
    expect(JSON.parse(rewrite.doc.all_versions[0].content).steps[0].assignee).toEqual(TARGET);
    expect(rewrite.doc.all_versions[1]).toEqual(all_versions[1]);
  });
});

describe('userMerge draft patches', () => {
  // `initial_value` is what undoing the draft restores: leaving it behind would re-inject the
  // source id on a rollback.
  it('should rewrite every side of the patch, initial_value included', () => {
    const patch = JSON.stringify({
      objectAssignee: { replaced_value: [SOURCE], added_value: [], removed_value: [], initial_value: [SOURCE] },
    });
    const rewritten = rewriteJson(patch, SOURCE, TARGET) as string;
    const parsed = JSON.parse(rewritten);
    expect(parsed.objectAssignee.replaced_value).toEqual([TARGET]);
    expect(parsed.objectAssignee.initial_value).toEqual([TARGET]);
  });

  it('should report a patch it cannot parse rather than rewrite it', () => {
    expect(rewriteJson(`{ broken ${SOURCE}`, SOURCE, TARGET)).toEqual('unparsable');
  });

  it('should report an id mentioned inside a value rather than as one', () => {
    const patch = JSON.stringify({ description: { replaced_value: [`written by ${SOURCE}`] } });
    expect(rewriteJson(patch, SOURCE, TARGET)).toEqual('textual');
  });
});

describe('userMerge serialized request access', () => {
  it('should remap the applicant of a request access record', () => {
    const record = JSON.stringify({ applicant_id: SOURCE, type: 'organization_sharing' });
    const rewrite = rewriteOf('case-rfi-request-access', { x_opencti_request_access: record }) as { doc: Record<string, string> };
    expect(JSON.parse(rewrite.doc.x_opencti_request_access).applicant_id).toEqual(TARGET);
  });
});
