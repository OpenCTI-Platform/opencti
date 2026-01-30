import { describe, expect, it } from 'vitest';
import '../../../src/modules/index';
import { ENTITY_TYPE_CONTAINER_REPORT, ENTITY_TYPE_MALWARE } from '../../../src/schema/stixDomainObject';
import type { Change } from '../../../src/types/event';
import { generateMessageFromChanges, humanizeRawValue } from '../../../src/database/data-changes';
import { type AttributeDefinition, authorizedMembers, authorizedMembersActivationDate, files, revoked, xOpenctiAliases } from '../../../src/schema/attribute-definition';
import { DefaultFormating } from '../../../src/utils/humanize';
import { height, type Measurement, weight } from '../../../src/modules/threatActorIndividual/threatActorIndividual';
import { workflowId } from '../../../src/modules/attributes/stixDomainObject-registrationAttributes';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../../src/modules/organization/organization-types';
import type { EntityFileReference } from '../../../src/modules/internal/document/document-types';

describe('generateUpdatePatchMessage tests', () => {
  // generate
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
    const message = generateMessageFromChanges({}, changes);
    expect(message).toEqual('replaces `updated` in `Description`');
  });
  it('should generate message for file update with markings', () => {
    const addFile: EntityFileReference = {
      id: 'import/Report/abc123/secret-doc.pdf',
      name: 'secret-doc.pdf',
      mime_type: 'application/pdf',
      version: '2025-11-12T15:28:21.073Z',
      file_markings: ['bff2afb7-03d3-40ad-bdd0-d6977f045ddg'],
    };
    const changes: Change[] = [
      {
        field: ENTITY_TYPE_CONTAINER_REPORT + '--' + files.name,
        changes_removed: [],
        changes_added: [{ raw: JSON.stringify(addFile) }],
      },
    ];
    const resolvedMap = { 'bff2afb7-03d3-40ad-bdd0-d6977f045ddg': 'TLP:GREEN' };
    const message = generateMessageFromChanges(resolvedMap, changes);
    expect(message).toEqual('add `secret-doc.pdf (TLP:GREEN)` in `Files`');
  });
  it('should generate message fail for unexisting attribute', () => {
    const changes: Change[] = [
      {
        field: ENTITY_TYPE_MALWARE + '--alias',
        changes_added: [{ raw: 'alias1' }],
        changes_removed: [{ raw: 'alias2' }],
      },
    ];
    const gen = () => generateMessageFromChanges({}, changes);
    expect(gen).toThrow();
  });
  it('should generate message for multi values field update', () => {
    const changes: Change[] = [
      {
        field: ENTITY_TYPE_IDENTITY_ORGANIZATION + '--' + xOpenctiAliases.name,
        changes_added: [{ raw: 'alias1' }],
        changes_removed: [{ raw: 'alias2' }],
      },
    ];
    const message = generateMessageFromChanges({}, changes);
    expect(message).toEqual('add `alias1` in `X_Aliases` | removes `alias2` in `X_Aliases`');
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
    const message = generateMessageFromChanges({}, changes);
    expect(message).toEqual('replaces `initial` in `Description`');
  });
  it('should generate message for simple field update if no value', () => {
    const changes: Change[] = [
      {
        field: ENTITY_TYPE_MALWARE + '--description',
        changes_added: [
          { raw: '' },
        ],
        changes_removed: [
          { raw: 'initial' },
        ],
      },
    ];
    const message = generateMessageFromChanges({}, changes);
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
    const message = generateMessageFromChanges({}, changes);
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
    const message = generateMessageFromChanges({}, changes);
    expect(message).toEqual('replaces `updated description` in `Description` - `updated name` in `Name`');
  });
  it('should generate message for Workflow status update', () => {
    const changes: Change[] = [
      {
        field: ENTITY_TYPE_CONTAINER_REPORT + '--x_opencti_workflow_id',
        changes_removed: [{ raw: 'bff2afb7-03d3-40ad-bdd0-d6977f045ddg' }],
        changes_added: [{ raw: 'bff2afb7-03d3-40ad-bdd0-d6977f045ddf' }],
      },
    ];
    const resolvedMap = {
      'bff2afb7-03d3-40ad-bdd0-d6977f045ddg': 'NEW',
      'bff2afb7-03d3-40ad-bdd0-d6977f045ddf': 'ANALYZED',
    };
    const message = generateMessageFromChanges(resolvedMap, changes);
    expect(message).toEqual('replaces `ANALYZED` in `Workflow status`');
  });
  // humanize
  it('should humanize authorizedMembers correctly handled', () => {
    let human = humanizeRawValue({}, authorizedMembers as AttributeDefinition, { raw: '-' }, DefaultFormating);
    expect(human).toEqual('Restricted');
    human = humanizeRawValue(
      { '88ec0c6a-13ce-5e39-b486-354fe4a7084f': 'Julien' },
      authorizedMembers as AttributeDefinition,
      { raw: '{"id":"88ec0c6a-13ce-5e39-b486-354fe4a7084f","access_right":"admin"}' },
      DefaultFormating,
    );
    expect(human).toEqual('Julien (admin)');
    human = humanizeRawValue(
      { 'c0171b19-4ec4-492f-ba44-b223642523ca': 'Filigran', '5f6d506d-dd03-438e-b137-245933538f02': 'Administrator' },
      authorizedMembers as AttributeDefinition,
      { raw: '{"id":"c0171b19-4ec4-492f-ba44-b223642523ca","access_right":"view","groups_restriction_ids":["5f6d506d-dd03-438e-b137-245933538f02"]}' },
      DefaultFormating,
    );
    expect(human).toEqual('Filigran x [Administrator] (view)');
  });
  it('should humanize weight and height correctly handled', () => {
    // Height
    let human = humanizeRawValue({}, height as AttributeDefinition, { raw: '-' }, DefaultFormating);
    expect(human).toEqual('Restricted');
    let measure: Measurement = { measure: 10, date_seen: '' };
    human = humanizeRawValue({}, height as AttributeDefinition, { raw: JSON.stringify(measure) }, DefaultFormating);
    expect(human).toEqual('10.00 (m) at Invalid date');
    measure = { measure: 20, date_seen: '2026-01-28T12:27:18Z' };
    human = humanizeRawValue({}, height as AttributeDefinition, { raw: JSON.stringify(measure) }, DefaultFormating);
    expect(human).toEqual('20.00 (m) at January 28 2026, 12:27:18 PM');
    // Weight
    human = humanizeRawValue({}, weight as AttributeDefinition, { raw: '-' }, DefaultFormating);
    expect(human).toEqual('Restricted');
    measure = { measure: 10, date_seen: '' };
    human = humanizeRawValue({}, weight as AttributeDefinition, { raw: JSON.stringify(measure) }, DefaultFormating);
    expect(human).toEqual('10.00 (kg) at Invalid date');
    measure = { measure: 20, date_seen: '2026-01-28T12:27:18Z' };
    human = humanizeRawValue({}, weight as AttributeDefinition, { raw: JSON.stringify(measure) }, DefaultFormating);
    expect(human).toEqual('20.00 (kg) at January 28 2026, 12:27:18 PM');
  });
  it('should humanize workflow correctly handled', () => {
    let human = humanizeRawValue({}, workflowId as AttributeDefinition, { raw: '-' }, DefaultFormating);
    expect(human).toEqual('Untranslated');
    human = humanizeRawValue({
      '5f6d506d-dd03-438e-b137-245933538f02': 'NEW',
    }, workflowId as AttributeDefinition, { raw: '5f6d506d-dd03-438e-b137-245933538f02' }, DefaultFormating);
    expect(human).toEqual('NEW');
  });
  it('should humanize standard attribute handled', () => {
    // Fake
    const fakeAttribute = { name: 'test', type: 'fake' } as unknown as AttributeDefinition;
    let human = humanizeRawValue({}, fakeAttribute, { raw: 'true' }, DefaultFormating);
    expect(human).toEqual('Untranslated');
    // Boolean
    human = humanizeRawValue({}, revoked, { raw: 'true' }, DefaultFormating);
    expect(human).toEqual('Yes');
    human = humanizeRawValue({}, revoked, { raw: '-' }, DefaultFormating);
    expect(human).toEqual('No');
    // Date
    human = humanizeRawValue({}, authorizedMembersActivationDate, { raw: '-' }, DefaultFormating);
    expect(human).toEqual('Invalid date');
    human = humanizeRawValue({}, authorizedMembersActivationDate, { raw: '2026-01-28T12:27:18Z' }, DefaultFormating);
    expect(human).toEqual('January 28 2026, 12:27:18 PM');
    human = humanizeRawValue({}, authorizedMembersActivationDate, { raw: '1970-01-01T00:00:00.000Z' }, DefaultFormating);
    expect(human).toEqual('');
    human = humanizeRawValue({}, authorizedMembersActivationDate, { raw: '2026-01-28T12:27:18Z' }, { ...DefaultFormating, date_format: 'MMM' });
    expect(human).toEqual('Jan');
  });
});
