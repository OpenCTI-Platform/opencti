import { describe, expect, it } from 'vitest';
import { computeMissingBuiltInExportIds, findMissingBuiltInElements } from '../../../src/migrations/1790755214072-add-export-id-to-built-in-entities';
import { generateBuiltInExportId } from '../../../src/schema/identifier';

const INDEX = 'test_internal_objects-000001';
let idCounter = 0;
const element = (entity_type: string, data: Record<string, any> = {}) => {
  idCounter += 1;
  return { _index: INDEX, internal_id: `id-${idCounter}`, entity_type, created_at: '2024-01-01T00:00:00.000Z', ...data };
};

describe('Migration add export_id to built-in entities', () => {
  it('should compute the same export_id as the platform initialization for built-in elements', () => {
    const elements = [
      element('Settings'),
      element('EntitySetting', { target_type: 'Report' }),
      element('ManagerConfiguration', { manager_id: 'FILE_INDEX_MANAGER' }),
      element('Capability', { name: 'KNOWLEDGE_KNUPDATE_KNDELETE' }),
      element('Role', { name: 'Administrator' }),
      element('Group', { name: 'Connectors' }),
      element('Marking-Definition', { definition_type: 'TLP', definition: 'TLP:AMBER+STRICT' }),
      element('Vocabulary', { category: 'report_types_ov', name: 'threat-report' }),
      element('Theme', { name: 'Filigran Dark', built_in: true }),
      element('DecayRule', { name: 'Built-in default', built_in: true }),
      element('EmailTemplate', { name: 'Built-In Template For Onboarding' }),
      element('RetentionRule', { name: 'History retention', scope: 'history' }),
      element('Notifier', { name: 'Sample of Microsoft Teams message for live trigger' }),
      element('FintelTemplate', { name: 'Executive Summary', settings_types: ['Case-Rfi'] }),
    ];
    const assignments = computeMissingBuiltInExportIds(elements);
    const exportIds = new Map(assignments.map((a) => [a.element.internal_id, a.export_id]));
    expect(exportIds).toEqual(new Map([
      [elements[0].internal_id, generateBuiltInExportId('Settings')],
      [elements[1].internal_id, generateBuiltInExportId('EntitySetting', { target_type: 'Report' })],
      [elements[2].internal_id, generateBuiltInExportId('ManagerConfiguration', { manager_id: 'FILE_INDEX_MANAGER' })],
      [elements[3].internal_id, generateBuiltInExportId('Capability', { name: 'KNOWLEDGE_KNUPDATE_KNDELETE' })],
      [elements[4].internal_id, generateBuiltInExportId('Role', { name: 'Administrator' })],
      [elements[5].internal_id, generateBuiltInExportId('Group', { name: 'Connectors' })],
      [elements[6].internal_id, generateBuiltInExportId('Marking-Definition', { definition_type: 'TLP', definition: 'TLP:AMBER+STRICT' })],
      [elements[7].internal_id, generateBuiltInExportId('Vocabulary', { category: 'report_types_ov', name: 'threat-report' })],
      [elements[8].internal_id, generateBuiltInExportId('Theme', { name: 'Filigran Dark' })],
      [elements[9].internal_id, generateBuiltInExportId('DecayRule', { name: 'Built-in default' })],
      [elements[10].internal_id, generateBuiltInExportId('EmailTemplate', { name: 'Built-In Template For Onboarding' })],
      [elements[11].internal_id, generateBuiltInExportId('RetentionRule', { scope: 'history' })],
      [elements[12].internal_id, generateBuiltInExportId('Notifier', { name: 'Sample of Microsoft Teams message for live trigger' })],
      [elements[13].internal_id, generateBuiltInExportId('FintelTemplate', { name: 'Executive Summary', target_type: 'Case-Rfi' })],
    ]));
  });

  it('should recognize built-in vocabularies whose key has surrounding spaces', () => {
    // malware_type_ov declares ' ransomware', stored as 'ransomware': the migration lists the stored names
    const vocabulary = element('Vocabulary', { category: 'malware_type_ov', name: 'ransomware' });
    expect(computeMissingBuiltInExportIds([vocabulary])).toEqual([
      { element: vocabulary, export_id: generateBuiltInExportId('Vocabulary', { category: 'malware_type_ov', name: 'ransomware' }) },
    ]);
  });

  it('should resolve the template of a built-in status', () => {
    const newTemplate = element('StatusTemplate', { name: 'NEW' });
    const customTemplate = element('StatusTemplate', { name: 'MY_STATUS' });
    const reportStatus = element('Status', { type: 'Report', scope: 'GLOBAL', template_id: newTemplate.internal_id });
    const rfiStatus = element('Status', { type: 'Case-Rfi', scope: 'REQUEST_ACCESS', template_id: newTemplate.internal_id });
    const customStatus = element('Status', { type: 'Report', scope: 'GLOBAL', template_id: customTemplate.internal_id });
    const otherTypeStatus = element('Status', { type: 'Grouping', scope: 'GLOBAL', template_id: newTemplate.internal_id });
    const assignments = computeMissingBuiltInExportIds([newTemplate, customTemplate, reportStatus, rfiStatus, customStatus, otherTypeStatus]);
    const exportIds = new Map(assignments.map((a) => [a.element.internal_id, a.export_id]));
    expect(exportIds).toEqual(new Map([
      [newTemplate.internal_id, generateBuiltInExportId('StatusTemplate', { name: 'NEW' })],
      [reportStatus.internal_id, generateBuiltInExportId('Status', { type: 'Report', scope: 'GLOBAL', template: 'NEW' })],
      [rfiStatus.internal_id, generateBuiltInExportId('Status', { type: 'Case-Rfi', scope: 'REQUEST_ACCESS', template: 'NEW' })],
    ]));
  });

  it('should ignore elements that are not built-in', () => {
    const elements = [
      element('Group', { name: 'My team' }),
      element('Theme', { name: 'Filigran Dark', built_in: false }),
      element('DecayRule', { name: 'My decay rule', built_in: false }),
      element('Vocabulary', { category: 'report_types_ov', name: 'my-report-type' }),
      element('Marking-Definition', { definition_type: 'STATEMENT', definition: 'Copyright' }),
      element('RetentionRule', { name: 'Knowledge retention', scope: 'knowledge' }),
      element('FintelTemplate', { name: 'My template', settings_types: ['Report'] }),
      element('Dashboard', { name: 'Administrators' }),
    ];
    expect(computeMissingBuiltInExportIds(elements)).toEqual([]);
  });

  it('should be idempotent and never give the same export_id to two elements', () => {
    const exportId = generateBuiltInExportId('Group', { name: 'Administrators' });
    const alreadyMigrated = element('Group', { name: 'Administrators', export_id: exportId });
    const copy = element('Group', { name: 'Administrators', created_at: '2020-01-01T00:00:00.000Z' });
    expect(computeMissingBuiltInExportIds([alreadyMigrated, copy])).toEqual([]);
    // Without export_id yet, the oldest one is the built-in
    const builtIn = element('Role', { name: 'Connector', created_at: '2020-01-01T00:00:00.000Z' });
    const newer = element('Role', { name: 'Connector', created_at: '2025-01-01T00:00:00.000Z' });
    expect(computeMissingBuiltInExportIds([newer, builtIn])).toEqual([
      { element: builtIn, export_id: generateBuiltInExportId('Role', { name: 'Connector' }) },
    ]);
  });

  it('should list the built-in elements that cannot be found', () => {
    const administrators = element('Group', { name: 'Administrators' });
    const renamedDefault = element('Group', { name: 'Everyone' });
    const alreadyMigratedThenRenamed = element('Group', { name: 'Robots', export_id: generateBuiltInExportId('Group', { name: 'Connectors' }) });
    const missing = findMissingBuiltInElements([administrators, renamedDefault, alreadyMigratedThenRenamed]);
    expect(missing.filter((m) => m.entity_type === 'Group')).toEqual([{ entity_type: 'Group', naturalKey: { name: 'Default' } }]);
    expect(missing.filter((m) => m.entity_type === 'Vocabulary')).toHaveLength(355);
    // Types whose instances are all built-in have no list of expected elements
    expect(missing.filter((m) => ['Settings', 'EntitySetting', 'ManagerConfiguration', 'Capability'].includes(m.entity_type))).toEqual([]);
  });
});
