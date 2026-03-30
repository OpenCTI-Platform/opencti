import { describe, expect, it } from 'vitest';
import '../../../src/modules/index';
import { ENTITY_TYPE_CONTAINER_REPORT, ENTITY_TYPE_MALWARE } from '../../../src/schema/stixDomainObject';
import type { Change } from '../../../src/types/event';
import {
  generateCreateMessage,
  generateDeleteMessage,
  generateMergeMessage,
  generateMessageFromChanges,
  generateRestoreMessage,
  humanizeRawValue,
} from '../../../src/database/data-changes';
import {
  type AttributeDefinition,
  authorizedMembers,
  authorizedMembersActivationDate,
  confidence,
  creators,
  files,
  lang,
  revoked,
  xOpenctiAliases,
} from '../../../src/schema/attribute-definition';
import { DefaultFormating } from '../../../src/utils/humanize';
import { height, type Measurement, weight } from '../../../src/modules/threatActorIndividual/threatActorIndividual';
import { workflowId } from '../../../src/modules/attributes/stixDomainObject-registrationAttributes';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../../src/modules/organization/organization-types';
import type { EntityFileReference } from '../../../src/modules/internal/document/document-types';
import { RELATION_USES } from '../../../src/schema/stixCoreRelationship';
import { RELATION_IN_PIR } from '../../../src/schema/internalRelationship';

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
    expect(message).toEqual('adds `secret-doc.pdf (TLP:GREEN)` in `Files`');
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
    expect(message).toEqual('adds `alias1` in `X_Aliases` | removes `alias2` in `X_Aliases`');
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
  it('should humanize creators correctly handled', () => {
    let human = humanizeRawValue({}, creators as AttributeDefinition, { raw: '-' }, DefaultFormating);
    expect(human).toEqual('Restricted');
    human = humanizeRawValue({
      '5f6d506d-dd03-438e-b137-245933538f02': 'Admin',
    }, creators as AttributeDefinition, { raw: '5f6d506d-dd03-438e-b137-245933538f02' }, DefaultFormating);
    expect(human).toEqual('Admin');
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
  it('should humanize numeric attribute correctly', () => {
    const human = humanizeRawValue({}, confidence as AttributeDefinition, { raw: '75' }, DefaultFormating);
    expect(human).toEqual('75');
  });
  it('should humanize string vocab/enum attribute correctly', () => {
    const human = humanizeRawValue({}, lang as AttributeDefinition, { raw: 'en' }, DefaultFormating);
    expect(human).toEqual('en');
  });
});

describe('generateCreateMessage tests', () => {
  it('should generate create message for a STIX entity', () => {
    const instance = { entity_type: ENTITY_TYPE_MALWARE, name: 'Test Malware' };
    expect(generateCreateMessage(instance)).toEqual('creates a Malware `Test Malware`');
  });
  it('should generate create message for a basic relationship', () => {
    const instance = {
      entity_type: RELATION_USES,
      from: { entity_type: ENTITY_TYPE_MALWARE, name: 'Source Malware' },
      to: { entity_type: ENTITY_TYPE_CONTAINER_REPORT, name: 'Target Report' },
    };
    expect(generateCreateMessage(instance)).toEqual(
      'creates the relation uses from `Source Malware` (Malware) to `Target Report` (Report)',
    );
  });
  it('should generate create message for a PIR relation', () => {
    const instance = {
      entity_type: RELATION_IN_PIR,
      from: { entity_type: ENTITY_TYPE_MALWARE, name: 'Source Malware' },
      to: { entity_type: ENTITY_TYPE_CONTAINER_REPORT, name: 'Target Report' },
    };
    expect(generateCreateMessage(instance)).toEqual(
      'Malware `Source Malware` added to Report `Target Report`',
    );
  });
  it('should return dash for an unknown entity type', () => {
    const instance = { entity_type: 'UnregisteredCustomEntityType', name: 'Unknown' };
    expect(generateCreateMessage(instance)).toEqual('-');
  });
});

describe('generateDeleteMessage tests', () => {
  it('should generate delete message for a STIX entity', () => {
    const instance = { entity_type: ENTITY_TYPE_MALWARE, name: 'Test Malware' };
    expect(generateDeleteMessage(instance)).toEqual('deletes a Malware `Test Malware`');
  });
  it('should generate delete message for a PIR relation', () => {
    const instance = {
      entity_type: RELATION_IN_PIR,
      from: { entity_type: ENTITY_TYPE_MALWARE, name: 'Source Malware' },
      to: { entity_type: ENTITY_TYPE_CONTAINER_REPORT, name: 'Target Report' },
    };
    expect(generateDeleteMessage(instance)).toEqual(
      'Malware `Source Malware` removed from Report `Target Report`',
    );
  });
});

describe('generateRestoreMessage tests', () => {
  it('should generate restore message for a STIX entity', () => {
    const instance = { entity_type: ENTITY_TYPE_MALWARE, name: 'Test Malware' };
    expect(generateRestoreMessage(instance)).toEqual('restores a Malware `Test Malware`');
  });
});

describe('generateMergeMessage tests', () => {
  it('should generate merge message with multiple sources', () => {
    const instance = { entity_type: ENTITY_TYPE_MALWARE, name: 'Merged Malware' };
    const sources = [
      { entity_type: ENTITY_TYPE_MALWARE, name: 'Source1' },
      { entity_type: ENTITY_TYPE_MALWARE, name: 'Source2' },
    ];
    expect(generateMergeMessage(instance, sources)).toEqual(
      'merges Malware `Source1, Source2` in `Merged Malware`',
    );
  });
});

describe('generateMessageFromChanges edge cases', () => {
  it('should generate message with only removes for a multiple field', () => {
    const changes: Change[] = [
      {
        field: ENTITY_TYPE_IDENTITY_ORGANIZATION + '--' + xOpenctiAliases.name,
        changes_added: [],
        changes_removed: [{ raw: 'alias1' }],
      },
    ];
    const message = generateMessageFromChanges({}, changes);
    expect(message).toEqual('removes `alias1` in `X_Aliases`');
  });
  it('should append "and N more operations" when changes exceed max', () => {
    const changes: Change[] = [
      { field: ENTITY_TYPE_MALWARE + '--description', changes_added: [{ raw: 'desc' }], changes_removed: [{ raw: 'old' }] },
      { field: ENTITY_TYPE_MALWARE + '--name', changes_added: [{ raw: 'new name' }], changes_removed: [{ raw: 'old name' }] },
      { field: ENTITY_TYPE_CONTAINER_REPORT + '--name', changes_added: [{ raw: 'report' }], changes_removed: [] },
      { field: ENTITY_TYPE_MALWARE + '--name', changes_added: [{ raw: 'extra' }], changes_removed: [] }, // 4th, only counted
    ];
    const message = generateMessageFromChanges({}, changes);
    expect(message).toContain('and 1 more operations');
  });
});
