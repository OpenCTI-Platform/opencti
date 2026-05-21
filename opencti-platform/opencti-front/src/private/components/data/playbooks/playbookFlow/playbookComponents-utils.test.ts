import { describe, expect, it } from 'vitest';
import { groupAndSortPlaybookComponents } from './playbookComponents-utils';
import type { PlaybookComponent } from '../types/playbook-types';

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

describe('groupAndSortPlaybookComponents', () => {
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
