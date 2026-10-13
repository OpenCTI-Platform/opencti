import { describe, expect, it } from 'vitest';
import { computeMissingBuiltInExportIds, findMissingBuiltInElements } from '../../../src/modules/globalExport/globalExport-migration-domain';
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
      element('Role', { name: 'Administrator' }),
      element('Group', { name: 'Connectors' }),
      element('Vocabulary', { category: 'report_types_ov', name: 'threat-report' }),
      element('Theme', { name: 'Filigran Dark', built_in: true }),
      element('EmailTemplate', { name: 'Built-In Template For Onboarding' }),
      element('Notifier', { name: 'Sample of Microsoft Teams message for live trigger' }),
      element('FintelTemplate', { name: 'Executive Summary', settings_types: ['Case-Rfi'] }),
    ];
    const assignments = computeMissingBuiltInExportIds(elements);
    const exportIds = new Map(assignments.map((a) => [a.element.internal_id, a.export_id]));
    expect(exportIds).toEqual(new Map([
      [elements[0].internal_id, generateBuiltInExportId('Settings')],
      [elements[1].internal_id, generateBuiltInExportId('Role', { name: 'Administrator' })],
      [elements[2].internal_id, generateBuiltInExportId('Group', { name: 'Connectors' })],
      [elements[3].internal_id, generateBuiltInExportId('Vocabulary', { category: 'report_types_ov', name: 'threat-report' })],
      [elements[4].internal_id, generateBuiltInExportId('Theme', { name: 'Filigran Dark' })],
      [elements[5].internal_id, generateBuiltInExportId('EmailTemplate', { name: 'Built-In Template For Onboarding' })],
      [elements[6].internal_id, generateBuiltInExportId('Notifier', { name: 'Sample of Microsoft Teams message for live trigger' })],
      [elements[7].internal_id, generateBuiltInExportId('FintelTemplate', { name: 'Executive Summary', target_type: 'Case-Rfi' })],
    ]));
  });

  it('should recognize built-in vocabularies whose key has surrounding spaces', () => {
    // malware_type_ov declares ' ransomware', stored as 'ransomware': the migration lists the stored names
    const vocabulary = element('Vocabulary', { category: 'malware_type_ov', name: 'ransomware' });
    expect(computeMissingBuiltInExportIds([vocabulary])).toEqual([
      { element: vocabulary, export_id: generateBuiltInExportId('Vocabulary', { category: 'malware_type_ov', name: 'ransomware' }) },
    ]);
  });

  it('should ignore elements that are not built-in', () => {
    const elements = [
      element('Group', { name: 'My team' }),
      element('Theme', { name: 'Filigran Dark', built_in: false }),
      element('Vocabulary', { category: 'report_types_ov', name: 'my-report-type' }),
      element('FintelTemplate', { name: 'My template', settings_types: ['Report'] }),
      element('Dashboard', { name: 'Administrators' }),
    ];
    expect(computeMissingBuiltInExportIds(elements)).toEqual([]);
  });

  it('should ignore the built-in elements of types without export_id', () => {
    // Their existing key is enough to find them on another platform, or they are not exported
    const elements = [
      element('Capability', { name: 'KNOWLEDGE_KNUPDATE_KNDELETE' }),
      element('EntitySetting', { target_type: 'Report' }),
      element('ManagerConfiguration', { manager_id: 'FILE_INDEX_MANAGER' }),
      element('Marking-Definition', { definition_type: 'TLP', definition: 'TLP:AMBER+STRICT' }),
      element('RetentionRule', { name: 'History retention', scope: 'history' }),
      element('StatusTemplate', { name: 'NEW' }),
      element('DecayRule', { name: 'Built-in default', built_in: true }),
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
    expect(missing.filter((m) => m.entity_type === 'Settings')).toEqual([{ entity_type: 'Settings', naturalKey: {} }]);
  });
});
