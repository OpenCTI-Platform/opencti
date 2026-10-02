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
import { rewriteDraftPatch, rewriteJson, rewriteTarget, userMergeDraftPatchIdPairs } from '../../../../src/modules/userMerge/userMerge-blobsHandler';
import type { UserMergeRewriteCandidate } from '../../../../src/modules/userMerge/userMerge-bulk';
import type { UserMergeHandlerContext } from '../../../../src/modules/userMerge/userMerge-handler';

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

describe('userMerge draft patches holding relationship edits', () => {
  const SOURCE_STANDARD = 'user--aaaaaaaa-5555-5555-8555-aaaaaaaaaaaa';
  const TARGET_STANDARD = 'user--bbbbbbbb-5555-5555-8555-bbbbbbbbbbbb';
  const pairs = [{ sourceId: SOURCE, targetId: TARGET }, { sourceId: SOURCE_STANDARD, targetId: TARGET_STANDARD }];
  const contextOf = (sourceStandard?: string, targetStandard?: string) => ({
    sourceId: SOURCE,
    targetId: TARGET,
    sourceUser: { internal_id: SOURCE, standard_id: sourceStandard },
    targetUser: { internal_id: TARGET, standard_id: targetStandard },
  }) as unknown as UserMergeHandlerContext;

  it('should pair the standard ids of both users with their internal ids', () => {
    expect(userMergeDraftPatchIdPairs(contextOf(SOURCE_STANDARD, TARGET_STANDARD))).toEqual(pairs);
  });

  it('should keep the internal ids alone when a standard id is missing', () => {
    expect(userMergeDraftPatchIdPairs(contextOf(SOURCE_STANDARD))).toEqual([pairs[0]]);
  });

  // An assignee edited in a draft is stored by standard id: the internal id never appears.
  it('should rewrite an edit the patch holds by standard id, initial_value included', () => {
    const patch = JSON.stringify({
      objectAssignee: { replaced_value: [], added_value: [SOURCE_STANDARD], removed_value: [], initial_value: [SOURCE_STANDARD] },
    });
    const parsed = JSON.parse(rewriteDraftPatch(patch, pairs) as string);
    expect(parsed.objectAssignee.added_value).toEqual([TARGET_STANDARD]);
    expect(parsed.objectAssignee.initial_value).toEqual([TARGET_STANDARD]);
  });

  it('should rewrite both forms when one patch holds them', () => {
    const patch = JSON.stringify({
      x_opencti_request_access: { replaced_value: [JSON.stringify({ applicant_id: SOURCE })] },
      objectParticipant: { added_value: [SOURCE_STANDARD, OTHER] },
    });
    const parsed = JSON.parse(rewriteDraftPatch(patch, pairs) as string);
    expect(JSON.parse(parsed.x_opencti_request_access.replaced_value[0]).applicant_id).toEqual(TARGET);
    expect(parsed.objectParticipant.added_value).toEqual([TARGET_STANDARD, OTHER]);
  });

  it('should collapse the target an edit already named', () => {
    const patch = JSON.stringify({ objectAssignee: { added_value: [SOURCE_STANDARD, TARGET_STANDARD] } });
    expect(JSON.parse(rewriteDraftPatch(patch, pairs) as string).objectAssignee.added_value).toEqual([TARGET_STANDARD]);
  });

  it('should rewrite the reference even when the other id is only mentioned', () => {
    const patch = JSON.stringify({ description: { replaced_value: [`written by ${SOURCE}`] }, objectAssignee: { added_value: [SOURCE_STANDARD] } });
    const parsed = JSON.parse(rewriteDraftPatch(patch, pairs) as string);
    expect(parsed.objectAssignee.added_value).toEqual([TARGET_STANDARD]);
    expect(parsed.description.replaced_value).toEqual([`written by ${SOURCE}`]);
  });

  it('should be a no-op on a second run', () => {
    const patch = JSON.stringify({ objectAssignee: { added_value: [SOURCE_STANDARD], initial_value: [] } });
    expect(rewriteDraftPatch(rewriteDraftPatch(patch, pairs), pairs)).toBeUndefined();
  });

  // Validation applies the add before the remove: a swap left as both would unassign the target.
  it('should keep the target assigned when the draft swapped the source for it', () => {
    const patch = JSON.stringify({ objectAssignee: { added_value: [TARGET_STANDARD], removed_value: [SOURCE_STANDARD], initial_value: [SOURCE_STANDARD] } });
    const parsed = JSON.parse(rewriteDraftPatch(patch, pairs) as string);
    expect(parsed.objectAssignee.added_value).toEqual([TARGET_STANDARD]);
    expect(parsed.objectAssignee.removed_value).toEqual([]);
    expect(parsed.objectAssignee.initial_value).toEqual([TARGET_STANDARD]);
  });

  it('should keep a removal of the source the draft did not balance with the target', () => {
    const patch = JSON.stringify({ objectAssignee: { added_value: [OTHER], removed_value: [SOURCE_STANDARD] } });
    const parsed = JSON.parse(rewriteDraftPatch(patch, pairs) as string);
    expect(parsed.objectAssignee.added_value).toEqual([OTHER]);
    expect(parsed.objectAssignee.removed_value).toEqual([TARGET_STANDARD]);
  });
});

describe('userMerge serialized request access', () => {
  it('should remap the applicant of a request access record', () => {
    const record = JSON.stringify({ applicant_id: SOURCE, type: 'organization_sharing' });
    const rewrite = rewriteOf('case-rfi-request-access', { x_opencti_request_access: record }) as { doc: Record<string, string> };
    expect(JSON.parse(rewrite.doc.x_opencti_request_access).applicant_id).toEqual(TARGET);
  });
});

describe('userMerge playbook definitions', () => {
  // The shape the playbook domain stores: each node configuration is serialized JSON, and the
  // filters inside it are serialized JSON again.
  const definitionOf = (user: string) => JSON.stringify({
    nodes: [
      {
        id: 'listen',
        component_id: 'PLAYBOOK_INTERNAL_DATA_STREAM',
        configuration: JSON.stringify({
          create: true,
          filters: JSON.stringify({ mode: 'and', filters: [{ key: ['creator_id'], values: [user], operator: 'eq', mode: 'or' }], filterGroups: [] }),
        }),
      },
      {
        id: 'restrict',
        component_id: 'PLAYBOOK_ACCESS_RESTRICTIONS_COMPONENT',
        configuration: JSON.stringify({ access_restrictions: [{ label: 'someone', type: 'User', value: user, accessRight: 'view', groupsRestriction: [] }] }),
      },
      {
        id: 'notify',
        component_id: 'PLAYBOOK_NOTIFIER_COMPONENT',
        configuration: JSON.stringify({ notifiers: [OTHER], authorized_members: [{ value: user }] }),
      },
    ],
    links: [],
  });

  it('should rewrite the users named inside the node configurations', () => {
    const rewrite = rewriteOf('playbook-definition', { playbook_definition: definitionOf(SOURCE) }) as { doc: Record<string, string> };
    expect(rewrite.doc.playbook_definition).toEqual(definitionOf(TARGET));
  });

  it('should be a no-op on a second run', () => {
    expect(rewriteOf('playbook-definition', { playbook_definition: definitionOf(TARGET) })).toBeUndefined();
  });
});

describe('userMerge draft patches holding serialized attributes', () => {
  // A draft of an attribute stored as serialized JSON carries it encoded once more in the patch.
  it('should rewrite the id inside a serialized attribute value', () => {
    const request = (user: string) => JSON.stringify({ applicant_id: user, type: 'organization_sharing' });
    const patch = JSON.stringify({ x_opencti_request_access: { replaced_value: [request(SOURCE)], initial_value: [request(OTHER)] } });
    const parsed = JSON.parse(rewriteJson(patch, SOURCE, TARGET) as string);
    expect(parsed.x_opencti_request_access.replaced_value).toEqual([request(TARGET)]);
    expect(parsed.x_opencti_request_access.initial_value).toEqual([request(OTHER)]);
  });
});
