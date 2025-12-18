import { describe, expect, it } from 'vitest';
import '../../../src/modules/index';
import { ENTITY_TYPE_CONTAINER_REPORT, ENTITY_TYPE_MALWARE } from '../../../src/schema/stixDomainObject';
import type { Change } from '../../../src/types/event';
import { generateMessageFromChanges } from '../../../src/database/generate-message';

describe('generateUpdatePatchMessage tests', () => {
  it('should generate message for simple field update', () => {
    const changes: Change[] = [
      {
        field: ENTITY_TYPE_MALWARE + '--description',
        changes_added: [
          { raw: 'updated' },
        ],
        changes_removed: [
          { raw: 'initial' },
        ],
      },
    ];
    const message = generateMessageFromChanges(changes);
    expect(message).toEqual('replaces `updated` in `Description`');
  });
  it('should generate message for simple field update if no previous value', () => {
    const changes: Change[] = [
      {
        field: ENTITY_TYPE_MALWARE + '--description',
        changes_added: [
          { raw: 'initial' },
        ],
        changes_removed: [],
      },
    ];
    const message = generateMessageFromChanges(changes);
    expect(message).toEqual('replaces `initial` in `Description`');
  });
  it('should generate message for simple field update if no value', () => {
    const changes: Change[] = [
      {
        field: ENTITY_TYPE_MALWARE + '--description',
        changes_added: [
          { raw: '', translated: 'nothing' },
        ],
        changes_removed: [
          { raw: 'initial' },
        ],
      },
    ];
    const message = generateMessageFromChanges(changes);
    expect(message).toEqual('replaces `nothing` in `Description`');
  });
  it('should generate message for simple field update with multiple values', () => {
    const changes: Change[] = [
      {
        field: ENTITY_TYPE_MALWARE + '--description',
        changes_added: [
          { raw: 'updated1' }, { raw: 'updated2' }, { raw: 'updated3' }, { raw: 'updated4' },
        ],
      },
    ];
    const message = generateMessageFromChanges(changes);
    expect(message).toEqual('replaces `updated1`, `updated2`, `updated3`, ... in `Description`');
  });
  it('should generate message for field update with multiple operations', () => {
    const changes: Change[] = [
      {
        field: ENTITY_TYPE_MALWARE + '--description',
        changes_added: [{ raw: 'updated description' }],
        changes_removed: [{ raw: 'initial description' }],
      },
      {
        field: ENTITY_TYPE_MALWARE + '--name',
        changes_added: [{ raw: 'updated name' }],
        changes_removed: [{ raw: 'initial name' }],
      },
    ];
    const message = generateMessageFromChanges(changes);
    expect(message).toEqual('replaces `updated description` in `Description` - `updated name` in `Name`');
  });
  it('should generate message for Workflow status update', () => {
    const changes: Change[] = [
      {
        field: ENTITY_TYPE_CONTAINER_REPORT + '--x_opencti_workflow_id',
        changes_removed: [{ raw: 'bff2afb7-03d3-40ad-bdd0-d6977f045ddg', translated: '{"bff2afb7-03d3-40ad-bdd0-d6977f045ddg":"NEW"}' }],
        changes_added: [{ raw: 'bff2afb7-03d3-40ad-bdd0-d6977f045ddf', translated: '{"bff2afb7-03d3-40ad-bdd0-d6977f045ddf":"ANALYZED"}' }],
      },
    ];
    const message = generateMessageFromChanges(changes);
    expect(message).toEqual('replaces `ANALYZED` in `Workflow status`');
  });
});
