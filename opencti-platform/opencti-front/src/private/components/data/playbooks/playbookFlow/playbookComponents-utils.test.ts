import { describe, expect, it } from 'vitest';
import { computeInitialComponentConfigValues, groupAndSortPlaybookComponents, NodeData } from './playbookComponents-utils';
import type { PlaybookComponent, PlaybookComponentConfigSchema } from '../types/playbook-types';

describe('playbookComponents-utils', () => {
  describe('groupAndSortPlaybookComponents', () => {
    const playbook = (overrides: Partial<PlaybookComponent> & { id: string; name: string }): PlaybookComponent => ({
      description: '',
      icon: '',
      category: 'start_playbook',
      is_entry_point: false,
      is_internal: false,
      configuration_schema: '',
      ports: [],
      ...overrides,
    });
    it('returns empty array for empty input', () => {
      expect(groupAndSortPlaybookComponents([], false)).toEqual([]);
    });

    it('filters by is_entry_point — returns only entry-point playbooks when isEntryPoint=true', () => {
      const playbooks = [
        playbook({ id: 'PLAYBOOK_INTERNAL_MANUAL_TRIGGER', name: 'Manual Trigger', category: 'start_playbook', is_entry_point: true }),
        playbook({ id: 'PLAYBOOK_LOGGER_COMPONENT', name: 'Log data', category: 'transform_and_enrich', is_entry_point: false }),
      ];
      const result = groupAndSortPlaybookComponents(playbooks, true);
      expect(result).toHaveLength(1);
      expect(result[0].category).toBe('start_playbook');
      expect(result[0].items).toHaveLength(1);
      expect(result[0].items[0].id).toBe('PLAYBOOK_INTERNAL_MANUAL_TRIGGER');
    });

    it('filters by is_entry_point — returns only non-entry-point playbooks when isEntryPoint=false', () => {
      const playbooks = [
        playbook({ id: 'PLAYBOOK_INTERNAL_MANUAL_TRIGGER', name: 'Manual Trigger', category: 'start_playbook', is_entry_point: true }),
        playbook({ id: 'PLAYBOOK_LOGGER_COMPONENT', name: 'Log data', category: 'transform_and_enrich', is_entry_point: false }),
      ];
      const result = groupAndSortPlaybookComponents(playbooks, false);
      expect(result).toHaveLength(1);
      expect(result[0].category).toBe('transform_and_enrich');
      expect(result[0].items[0].id).toBe('PLAYBOOK_LOGGER_COMPONENT');
    });

    it('sorts components alphabetically within a group', () => {
      const playbooks = [
        playbook({ id: 'PLAYBOOK_REDUCING_COMPONENT', name: 'Reduce knowledge', category: 'transform_and_enrich', is_entry_point: false }),
        playbook({ id: 'PLAYBOOK_RULE_COMPONENT', name: 'Apply predefined rule', category: 'transform_and_enrich', is_entry_point: false }),
        playbook({ id: 'PLAYBOOK_LOGGER_COMPONENT', name: 'Log data in standard output', category: 'transform_and_enrich', is_entry_point: false }),
      ];
      const result = groupAndSortPlaybookComponents(playbooks, false);
      expect(result[0].items[0].name).toContain('Apply predefined rule');
      expect(result[0].items[1].name).toContain('Log data in standard output');
      expect(result[0].items[2].name).toContain('Reduce knowledge');
    });

    it('respects PLAYBOOK_CATEGORY_ORDER group sequence regardless of input order', () => {
      const playbooks = [
        playbook({ id: 'PLAYBOOK_NOTIFIER_COMPONENT', name: 'Send to notifier', category: 'end_playbook', is_entry_point: false }),
        playbook({ id: 'PLAYBOOK_SHARING_COMPONENT', name: 'Share with organizations', category: 'share_and_access', is_entry_point: false }),
        playbook({ id: 'PLAYBOOK_LOGGER_COMPONENT', name: 'Log data', category: 'transform_and_enrich', is_entry_point: false }),
      ];
      const result = groupAndSortPlaybookComponents(playbooks, false);
      const categories = result.map((g) => g.category);
      expect(categories).toEqual(['transform_and_enrich', 'share_and_access', 'end_playbook']);
    });

    it('omits groups that have no matching components', () => {
      const playbooks = [
        playbook({ id: 'PLAYBOOK_LOGGER_COMPONENT', name: 'Log data', category: 'transform_and_enrich', is_entry_point: false }),
      ];
      const result = groupAndSortPlaybookComponents(playbooks, false);
      expect(result).toHaveLength(1);
      expect(result[0].category).toBe('transform_and_enrich');
    });

    it('handles a single component correctly', () => {
      const playbooks = [
        playbook({ id: 'PLAYBOOK_INGESTION_COMPONENT', name: 'Send for ingestion', category: 'end_playbook', is_entry_point: false }),
      ];
      const result = groupAndSortPlaybookComponents(playbooks, false);
      expect(result).toHaveLength(1);
      expect(result[0].category).toBe('end_playbook');
      expect(result[0].items).toHaveLength(1);
    });
  });

  describe('computeInitialComponentConfigValues', () => {
    const COMPONENT_A = { id: 'PLAYBOOK_COMPONENT_A', name: 'Component A' } as unknown as PlaybookComponent;
    const COMPONENT_B = { id: 'PLAYBOOK_COMPONENT_B', name: 'Component B' } as unknown as PlaybookComponent;

    const schemaA = {
      type: 'object',
      required: [],
      properties: {
        filters: { type: 'string', $ref: 'Filters', default: '' },
        excludeMainElement: { type: 'boolean', $ref: 'Exclude main', default: false },
      },
    } as unknown as PlaybookComponentConfigSchema;

    const schemaB = {
      type: 'object',
      required: [],
      properties: {
        wrap_in_container: { type: 'boolean', $ref: 'Wrap', default: true },
      },
    } as unknown as PlaybookComponentConfigSchema;

    it('uses schema defaults when there is no existing config', () => {
      const result = computeInitialComponentConfigValues({
        action: 'add',
        currentConfig: null,
        configurationSchema: schemaB,
        nodeData: undefined,
        selectedComponent: COMPONENT_B,
      });

      expect(result.name).toBe('Component B');
      expect(result.description).toBe('');
      expect((result).wrap_in_container).toBe(true);
    });

    it('uses schema defaults when action is replace', () => {
      const oldConfig = { filters: '{"mode":"and","filters":[]}', excludeMainElement: true };

      const result = computeInitialComponentConfigValues({
        action: 'replace',
        currentConfig: oldConfig,
        configurationSchema: schemaB,
        nodeData: { name: 'My node', component: COMPONENT_A } as unknown as NodeData,
        selectedComponent: COMPONENT_B,
      });

      // Should use default props of component B
      expect(result.name).toBe('Component B');
      expect(result.description).toBe('');
      expect((result).wrap_in_container).toBe(true);
      // Should not contain props of component A
      expect((result).filters).toBeUndefined();
      expect((result).excludeMainElement).toBeUndefined();
    });

    it('keeps existing config when action is config (editing same component)', () => {
      const existingConfig = { filters: '{"mode":"and","filters":[{"key":"type"}]}' };

      const result = computeInitialComponentConfigValues({
        action: 'config',
        currentConfig: existingConfig,
        nodeData: { name: 'My node', description: 'desc', component: COMPONENT_A } as unknown as NodeData,
        configurationSchema: schemaA,
        selectedComponent: COMPONENT_A,
      });

      expect(result.name).toBe('My node');
      expect(result.description).toBe('desc');
      expect((result).filters).toBe('{"mode":"and","filters":[{"key":"type"}]}');
    });

    it('does not leak old config properties into new component on replace', () => {
      const oldConfig = {
        filters: '{"mode":"and","filters":[]}',
        excludeMainElement: true,
        newContainer: false,
        actions: [],
        applyToElements: 'all',
        wrap_in_container: false,
      };

      const result = computeInitialComponentConfigValues({
        action: 'replace',
        currentConfig: oldConfig,
        nodeData: { name: 'Old node', component: COMPONENT_A } as unknown as NodeData,
        selectedComponent: COMPONENT_B,
        configurationSchema: schemaB,
      });

      // Only props from new schame should be there
      expect((result).wrap_in_container).toBe(true); // default from schema B
      expect((result).excludeMainElement).toBeUndefined();
      expect((result).newContainer).toBeUndefined();
      expect((result).actions).toBeUndefined();
      expect((result).applyToElements).toBeUndefined();
      expect((result).filters).toBeUndefined();
    });
  });
});
