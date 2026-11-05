import { describe, expect, it } from 'vitest';
import '../../../src/modules/index';
import { buildBundleElement } from '../../../src/manager/taskManager';
import { convertStoreToStix_2_1 } from '../../../src/database/stix-2-1-converter';
import { STIX_EXT_OCTI } from '../../../src/types/stix-2-1-extensions';
import {
  ACTION_TYPE_ADD_GROUPS,
  ACTION_TYPE_ADD_ORGANIZATIONS,
  ACTION_TYPE_ADD_RELATED_COVERED_ENTITIES,
  ACTION_TYPE_ENRICHMENT,
  ACTION_TYPE_ENROLL_PLAYBOOK,
  ACTION_TYPE_MERGE,
  ACTION_TYPE_REMOVE_AUTH_MEMBERS,
  ACTION_TYPE_REMOVE_FROM_DRAFT,
  ACTION_TYPE_REMOVE_GROUPS,
  ACTION_TYPE_REMOVE_ORGANIZATIONS,
  ACTION_TYPE_RESTORE,
  ACTION_TYPE_RULE_APPLY,
  ACTION_TYPE_RULE_CLEAR,
  ACTION_TYPE_RULE_ELEMENT_RESCAN,
  ACTION_TYPE_SEND_EMAIL,
  ACTION_TYPE_SHARE,
  ACTION_TYPE_UNSHARE,
} from '../../../src/domain/backgroundTask-common';
import type { StoreCommon } from '../../../src/types/store';
import { MALWARE_INSTANCE } from '../database/stix-2-0-converter-fixtures/SDOs/arsenal/malware';
import { REPORT_INSTANCE } from '../database/stix-2-0-converter-fixtures/SDOs/containers/report';
import { IPV4_INSTANCE } from '../database/stix-2-0-converter-fixtures/SCOs/ipv4-addr';
import { RELATION_INSTANCE } from '../database/stix-2-0-converter-fixtures/SROs/relation';
import { SIGHTING_INSTANCE } from '../database/stix-2-0-converter-fixtures/SROs/sightings';
import { bundleOf, expectNoOrphanFixtures, type GeneratedFixture, writeOrCheckFixture } from './import-conformance-utils';

// Import conformance fixtures for the operations carried as bundles (pycti's
// apply_opencti_operation), in the two forms an importer receives them:
// - ext: the operation in the OpenCTI extension, built by the platform's own producers
//   (background tasks through buildBundleElement, PIR manager);
// - top: a stream event (sync), which the worker turns into a bundle with the operation at the
//   top level (opencti-worker push_handler.py, mirrored by the client-python recorder).

const element = (instance: object, internalId: string) => ({ internal_id: internalId, ...instance }) as Record<string, unknown>;
const internalElement = (entityType: string, standardId: string, internalId: string) => ({ internal_id: internalId, standard_id: standardId, entity_type: entityType });

const MALWARE = element(MALWARE_INSTANCE, MALWARE_INSTANCE.id);
const REPORT = element(REPORT_INSTANCE, (REPORT_INSTANCE as { id: string }).id);
const IPV4 = element(IPV4_INSTANCE, IPV4_INSTANCE.id);
const RELATION = element(RELATION_INSTANCE, RELATION_INSTANCE.id);
const SIGHTING = element(SIGHTING_INSTANCE, SIGHTING_INSTANCE.id);
const SECURITY_COVERAGE = internalElement('Security-Coverage', 'security-coverage--20000000-0000-4000-8000-000000000903', '10000000-0000-4000-8000-000000000903');
const USER = internalElement('User', 'user--20000000-0000-4000-8000-000000000a01', '10000000-0000-4000-8000-000000000a01');
const INTERNAL_TARGETS = [
  USER,
  internalElement('Notification', 'notification--20000000-0000-4000-8000-000000000a02', '10000000-0000-4000-8000-000000000a02'),
  internalElement('DeleteOperation', 'deleteoperation--20000000-0000-4000-8000-000000000a03', '10000000-0000-4000-8000-000000000a03'),
  internalElement('InternalFile', 'import/global/report.pdf', 'import/global/report.pdf'),
  internalElement('DraftWorkspace', 'draftworkspace--20000000-0000-4000-8000-000000000a05', '10000000-0000-4000-8000-000000000a05'),
  internalElement('Workspace', 'workspace--20000000-0000-4000-8000-000000000a06', '10000000-0000-4000-8000-000000000a06'),
  internalElement('PublicDashboard', 'publicdashboard--20000000-0000-4000-8000-000000000a07', '10000000-0000-4000-8000-000000000a07'),
  internalElement('Playbook', 'playbook--20000000-0000-4000-8000-000000000a08', '10000000-0000-4000-8000-000000000a08'),
  internalElement('Group', 'group--20000000-0000-4000-8000-000000000a09', '10000000-0000-4000-8000-000000000a09'),
];
const EXTERNAL_REFERENCE = internalElement('External-Reference', 'external-reference--20000000-0000-4000-8000-000000000a14', '10000000-0000-4000-8000-000000000a14');
const INDICATOR = internalElement('Indicator', 'indicator--20000000-0000-4000-8000-000000000a15', '10000000-0000-4000-8000-000000000a15');
const NOTIFICATION = INTERNAL_TARGETS[1];
// Meta objects are deleted through stixEdit
const LABEL = internalElement('Label', 'label--20000000-0000-4000-8000-000000000a16', '10000000-0000-4000-8000-000000000a16');
const ROLE = internalElement('Role', 'role--20000000-0000-4000-8000-000000000a17', '10000000-0000-4000-8000-000000000a17');
const WORK = internalElement('Work', 'work--20000000-0000-4000-8000-000000000a18', '10000000-0000-4000-8000-000000000a18');
// Internal types pycti has no helper for: their delete fails (accepted, declared in the fixture)
const UNSUPPORTED_TARGETS = [
  internalElement('Capability', 'capability--20000000-0000-4000-8000-000000000a10', '10000000-0000-4000-8000-000000000a10'),
  internalElement('Settings', 'settings--20000000-0000-4000-8000-000000000a11', '10000000-0000-4000-8000-000000000a11'),
];

const values = (...items: unknown[]) => [{ context: { values: items } }];
const ORGANIZATION_ID = '10000000-0000-4000-8000-000000000b01';

interface TaskCase {
  operation: string;
  actionType: string;
  operations: unknown[];
  target: Record<string, unknown>;
  // Distinguishes two cases of the same operation on the same type
  variant?: string;
  // Why the case is built by hand, when no producer of the platform emits it this way
  note?: string;
  expectErrors?: boolean;
}

const replaceDescription = (description: string) => ({ type: 'REPLACE', context: { field: 'description', type: 'ATTRIBUTE', values: [description] } });
// No producer of the platform patches x_opencti_files (connectors and playbooks may): the
// patch is built the way the task manager would build it for that key
const FILES_NOTE = 'x_opencti_files patch built by hand: no producer of the platform emits it';
const addFiles = {
  type: 'ADD',
  context: {
    field: 'x_opencti_files',
    type: 'ATTRIBUTE',
    values: [
      { name: 'evidence.txt', data: Buffer.from('conformance evidence').toString('base64'), mime_type: 'text/plain', object_marking_refs: ['marking-definition--89484dde-e3d2-547f-a6c6-d14824429eb1'], no_trigger_import: true },
      { name: 'no-data.txt', mime_type: 'text/plain' },
    ],
  },
};

const TASK_CASES: TaskCase[] = [
  {
    operation: 'patch',
    actionType: 'KNOWLEDGE_CHANGE',
    operations: [
      { type: 'REPLACE', context: { field: 'description', type: 'ATTRIBUTE', values: ['Updated description'] } },
      { type: 'ADD', context: { field: 'object-label', type: 'RELATION', values: ['10000000-0000-4000-8000-000000000c01'] } },
    ],
    target: MALWARE,
  },
  {
    operation: 'patch',
    actionType: 'KNOWLEDGE_CHANGE',
    operations: [{ type: 'REPLACE', context: { field: 'description', type: 'ATTRIBUTE', values: ['Updated description'] } }],
    target: IPV4,
  },
  {
    operation: 'patch',
    actionType: 'KNOWLEDGE_CHANGE',
    operations: [{ type: 'REPLACE', context: { field: 'account_status', type: 'ATTRIBUTE', values: ['Locked'] } }],
    target: USER,
  },
  ...[RELATION, SIGHTING, INDICATOR].map((target) => ({ operation: 'patch', actionType: 'KNOWLEDGE_CHANGE', operations: [replaceDescription('Updated description')], target })),
  { operation: 'patch', actionType: 'KNOWLEDGE_CHANGE', operations: [addFiles], target: MALWARE, variant: 'files', note: FILES_NOTE },
  { operation: 'patch', actionType: 'KNOWLEDGE_CHANGE', operations: [replaceDescription('Updated description'), addFiles], target: EXTERNAL_REFERENCE, note: FILES_NOTE },
  {
    operation: 'patch',
    actionType: 'KNOWLEDGE_CHANGE',
    operations: [{ type: 'REPLACE', context: { field: 'is_read', type: 'ATTRIBUTE', values: [true] } }],
    target: NOTIFICATION,
  },
  ...[MALWARE, RELATION, SIGHTING, IPV4, EXTERNAL_REFERENCE, SECURITY_COVERAGE, LABEL, ROLE, WORK, ...INTERNAL_TARGETS].map((target) => ({ operation: 'delete', actionType: 'KNOWLEDGE_TRASH', operations: [], target })),
  ...UNSUPPORTED_TARGETS.map((target) => ({ operation: 'delete', actionType: 'KNOWLEDGE_TRASH', operations: [], target, expectErrors: true })),
  { operation: 'delete_force', actionType: 'KNOWLEDGE_REMOVE', operations: [], target: MALWARE },
  { operation: 'restore', actionType: ACTION_TYPE_RESTORE, operations: [], target: INTERNAL_TARGETS[2] },
  { operation: 'enrichment', actionType: ACTION_TYPE_ENRICHMENT, operations: values('10000000-0000-4000-8000-000000000d01'), target: IPV4 },
  { operation: 'merge', actionType: ACTION_TYPE_MERGE, operations: values('10000000-0000-4000-8000-000000000e01', '10000000-0000-4000-8000-000000000e02'), target: MALWARE },
  ...[MALWARE, RELATION, SIGHTING].map((target) => ({ operation: 'revert_draft', actionType: ACTION_TYPE_REMOVE_FROM_DRAFT, operations: [], target })),
  { operation: 'rule_apply', actionType: ACTION_TYPE_RULE_APPLY, operations: [{ context: { rule_id: 'attribution_attribution' } }], target: RELATION },
  { operation: 'rule_clear', actionType: ACTION_TYPE_RULE_CLEAR, operations: [{ context: { rule_id: 'attribution_attribution' } }], target: RELATION },
  // pycti calls rules_rescan_async, the entity defines rule_rescan_async: the operation fails today
  { operation: 'rules_rescan', actionType: ACTION_TYPE_RULE_ELEMENT_RESCAN, operations: [], target: MALWARE, expectErrors: true },
  ...[REPORT, RELATION, SIGHTING].flatMap((target) => [
    { operation: 'share', actionType: ACTION_TYPE_SHARE, operations: values(ORGANIZATION_ID), target },
    { operation: 'unshare', actionType: ACTION_TYPE_UNSHARE, operations: values(ORGANIZATION_ID), target },
  ]),
  { operation: 'clear_access_restriction', actionType: ACTION_TYPE_REMOVE_AUTH_MEMBERS, operations: [], target: MALWARE },
  {
    operation: 'add_related_covered_entities',
    actionType: ACTION_TYPE_ADD_RELATED_COVERED_ENTITIES,
    operations: [{
      id: 'security-coverage-result--20000000-0000-4000-8000-000000000905',
      relationships_config: {
        description: 'Covered by the scenario',
        start_time: '2025-01-01T00:00:00.000Z',
        coverage_information: [{ coverage_name: 'detection', coverage_score: 60 }, { coverage_name: 'no score' }],
        confidence: 80,
      },
    }],
    target: SECURITY_COVERAGE,
  },
  { operation: 'add_organizations', actionType: ACTION_TYPE_ADD_ORGANIZATIONS, operations: values(ORGANIZATION_ID), target: USER },
  { operation: 'remove_organizations', actionType: ACTION_TYPE_REMOVE_ORGANIZATIONS, operations: values(ORGANIZATION_ID), target: USER },
  { operation: 'add_groups', actionType: ACTION_TYPE_ADD_GROUPS, operations: values('10000000-0000-4000-8000-000000000a09'), target: USER },
  { operation: 'remove_groups', actionType: ACTION_TYPE_REMOVE_GROUPS, operations: values('10000000-0000-4000-8000-000000000a09'), target: USER },
  { operation: 'send_email', actionType: ACTION_TYPE_SEND_EMAIL, operations: values('10000000-0000-4000-8000-000000000f01'), target: USER },
  { operation: 'enroll_playbook', actionType: ACTION_TYPE_ENROLL_PLAYBOOK, operations: values({ id: '10000000-0000-4000-8000-000000000a08' }), target: MALWARE },
];

const typeName = (target: Record<string, unknown>) => String(target.entity_type).toLowerCase();

const taskFixtures = (): GeneratedFixture[] => TASK_CASES.map(({ operation, actionType, operations, target, variant, note, expectErrors }) => ({
  path: `ops/${operation}/task-${typeName(target)}${variant ? `-${variant}` : ''}.ext`,
  source: `C: buildBundleElement(${typeName(target)}, ${actionType}), opencti-graphql src/manager/taskManager.js${note ? `\n${note}` : ''}`,
  input: bundleOf(buildBundleElement(target, actionType, operations)),
  ...(expectErrors ? { call: { expect_errors: true } } : {}),
}));

// The PIR manager pushes the PIR itself with the operation in its extension and an input
// (src/manager/pirManager.ts, pirFlagElementToQueue and pirUnflagElementFromQueue)
const PIR_INSTANCE = {
  internal_id: '10000000-0000-4000-8000-000000000a12',
  standard_id: 'pir--20000000-0000-4000-8000-000000000a12',
  entity_type: 'Pir',
  base_type: 'ENTITY',
  parent_types: ['Basic-Object', 'Internal-Object'],
  name: 'Ransomware targeting energy',
  created_at: '2025-01-01T00:00:00.000Z',
  updated_at: '2025-01-02T00:00:00.000Z',
};
const pirFixture = (operation: string, input: Record<string, unknown>): GeneratedFixture => {
  const stixPir = convertStoreToStix_2_1(PIR_INSTANCE as unknown as StoreCommon) as unknown as Record<string, Record<string, Record<string, unknown>>>;
  stixPir.extensions[STIX_EXT_OCTI].opencti_operation = operation;
  return {
    path: `ops/${operation}/pir.ext`,
    source: 'C: convertStoreToStix_2_1(PIR) + operation, as opencti-graphql src/manager/pirManager.ts builds it',
    input: bundleOf({ ...stixPir, input }),
    call: { update: true },
  };
};
// pirFlagElementToQueue: the matching criteria are the PIR's parsed criteria (ParsedPirCriterion)
const PIR_FLAG_INPUT = {
  relationshipId: '10000000-0000-4000-8000-000000000a13',
  sourceId: MALWARE_INSTANCE.id,
  matchingCriteria: [{
    weight: 2,
    filters: { mode: 'and', filters: [{ key: ['toId'], values: ['10000000-0000-4000-8000-000000000a19'], operator: 'eq', mode: 'or' }], filterGroups: [] },
  }],
  relationshipAuthorId: '10000000-0000-4000-8000-000000000a20',
};
// pirUnflagElementFromQueue
const PIR_UNFLAG_INPUT = { relationshipId: '10000000-0000-4000-8000-000000000a13', sourceId: MALWARE_INSTANCE.id };

// Stream events a sync replays (the worker's "event" messages)
const malwareData = () => convertStoreToStix_2_1(MALWARE_INSTANCE as unknown as StoreCommon);
const EVENT_CASES: { name: string; event: Record<string, unknown> }[] = [
  { name: 'create', event: { type: 'create', data: malwareData() } },
  { name: 'update', event: { type: 'update', data: malwareData(), context: { patch: [] } } },
  { name: 'merge', event: { type: 'merge', data: malwareData(), context: { sources: [{ id: 'malware--20000000-0000-4000-8000-000000000e01' }] } } },
  { name: 'delete', event: { type: 'delete', data: malwareData() } },
];
const eventFixtures = (): GeneratedFixture[] => EVENT_CASES.map(({ name, event }) => ({
  path: `ops/${name}/event-malware.top`,
  source: 'C: stream event over convertStoreToStix_2_1(MALWARE_INSTANCE), as a sync pushes it to the worker',
  input: event,
  call: { message_type: 'event' },
}));

describe('Import conformance fixtures for the operations', () => {
  const fixtures = [
    ...taskFixtures(),
    pirFixture('pir_flag_element', PIR_FLAG_INPUT),
    pirFixture('pir_unflag_element', PIR_UNFLAG_INPUT),
    ...eventFixtures(),
  ];
  it('should give one path per fixture', () => {
    expect(new Set(fixtures.map((fixture) => fixture.path)).size).toEqual(fixtures.length);
  });
  it.each(fixtures.map((fixture) => [fixture.path, fixture] as const))('%s', (_, fixture) => {
    writeOrCheckFixture(fixture);
  });
  it('should leave no fixture it does not generate anymore', () => {
    expectNoOrphanFixtures('C:', fixtures);
  });
});
