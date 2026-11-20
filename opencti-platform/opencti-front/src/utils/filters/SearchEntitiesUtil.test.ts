import { describe, expect, it } from 'vitest';
import type { FilterOptionValue } from '@components/common/lists/FilterAutocomplete';
import { buildMembersOptions, getOptionsFromEntities, rankOptions } from './SearchEntitiesUtil';
import { ME_FILTER_VALUE } from './filtersUtils';

// an entity found by a search for a typed term, so ranked by relevance
const entity = (label: string, type: string, value = `${type}--${label}`): FilterOptionValue => ({
  label,
  value,
  type,
  parentTypes: ['Stix-Domain-Object'],
  ranked: true,
});

const labels = (options: FilterOptionValue[]) => options.map((o) => o.label);

describe('getOptionsFromEntities', () => {
  describe('when nothing is typed', () => {
    it('orders the groups then the labels alphabetically, even the options ranked by a previous search', () => {
      const entities = {
        id: [entity('Zeus', 'Malware'), entity('APT28', 'Intrusion-Set'), entity('Agent Tesla', 'Malware')],
      };
      const expected = ['APT28', 'Agent Tesla', 'Zeus'];
      expect(labels(getOptionsFromEntities(entities, {}, 'id'))).toEqual(expected);
      expect(labels(getOptionsFromEntities(entities, {}, 'id', ''))).toEqual(expected);
      expect(labels(getOptionsFromEntities(entities, {}, 'id', '   '))).toEqual(expected);
    });

    it('keeps "No label" and the dynamic @me user at the top', () => {
      const labelEntities = {
        objectLabel: [
          { label: 'malicious', value: 'l1', type: 'Label' },
          { label: 'No label', value: null, type: 'Label' },
          { label: 'abuse', value: 'l2', type: 'Label' },
        ] as FilterOptionValue[],
      };
      expect(labels(getOptionsFromEntities(labelEntities, {}, 'objectLabel'))).toEqual(['No label', 'abuse', 'malicious']);

      const userEntities = {
        creator_id: [
          { label: 'Admin', value: 'u1', type: 'User', group: 'User' },
          { label: 'me', value: ME_FILTER_VALUE, type: 'User', group: 'User' },
        ] as FilterOptionValue[],
      };
      expect(labels(getOptionsFromEntities(userEntities, {}, 'creator_id'))).toEqual(['me', 'Admin']);
    });
  });

  describe('when a term is typed', () => {
    it('keeps the order of the search within a group', () => {
      const entities = {
        id: [entity('Lazarus', 'Malware'), entity('Black Lazarus loader', 'Malware'), entity('Alazarusoft', 'Malware')],
      };
      expect(labels(getOptionsFromEntities(entities, {}, 'id', 'lazarus'))).toEqual(['Lazarus', 'Black Lazarus loader', 'Alazarusoft']);
    });

    it('groups the entities by type, in the order of the first entity of each group', () => {
      const entities = {
        id: [
          entity('APT', 'Intrusion-Set'),
          entity('Mimikatz usage by APT groups', 'Attack-Pattern'),
          entity('APT28', 'Intrusion-Set'),
          entity('Captain', 'Attack-Pattern'),
        ],
      };
      const options = getOptionsFromEntities(entities, {}, 'id', 'apt');
      expect(labels(options)).toEqual(['APT', 'APT28', 'Mimikatz usage by APT groups', 'Captain']);
      expect(options.map((o) => o.group)).toEqual(['Intrusion-Set', 'Intrusion-Set', 'Attack-Pattern', 'Attack-Pattern']);
    });

    it('orders the groups by their first entity whose label contains the term, as the others are not shown', () => {
      const entities = {
        id: [
          entity('Hidden Cobra', 'Intrusion-Set'), // found by the search on its aliases, hidden by the autocomplete
          entity('Lazarus', 'Malware'),
          entity('Lazarus Group Campaign', 'Intrusion-Set'),
        ],
      };
      const options = getOptionsFromEntities(entities, {}, 'id', 'lazarus');
      expect(labels(options)).toEqual(['Lazarus', 'Hidden Cobra', 'Lazarus Group Campaign']);
    });

    it('compares the labels to the term case and accent insensitively', () => {
      const entities = {
        id: [entity('Aurora', 'Intrusion-Set'), entity('Opération Aurora', 'Campaign')],
      };
      expect(labels(getOptionsFromEntities(entities, {}, 'id', 'OPERATION'))).toEqual(['Opération Aurora', 'Aurora']);
    });

    it('orders a group without any shown entity by its first entity, after the groups with shown entities', () => {
      const entities = {
        id: [
          entity('Hidden Cobra', 'Intrusion-Set'),
          entity('Dropper', 'Malware'),
          entity('Lazarus', 'Campaign'),
        ],
      };
      const options = getOptionsFromEntities(entities, {}, 'id', 'lazarus');
      expect(labels(options)).toEqual(['Lazarus', 'Hidden Cobra', 'Dropper']);
    });

    it('keeps "No label" and the dynamic @me user at the top', () => {
      const labelEntities = {
        objectLabel: [
          { label: 'malicious', value: 'l1', type: 'Label', ranked: true },
          { label: 'No label', value: null, type: 'Label' },
          { label: 'mal', value: 'l2', type: 'Label', ranked: true },
        ] as FilterOptionValue[],
      };
      expect(labels(getOptionsFromEntities(labelEntities, {}, 'objectLabel', 'mal'))).toEqual(['No label', 'malicious', 'mal']);

      const userEntities = {
        creator_id: [
          { label: 'Admin', value: 'u1', type: 'User', group: 'User' },
          { label: 'me', value: ME_FILTER_VALUE, type: 'User', group: 'User' },
        ] as FilterOptionValue[],
      };
      expect(labels(getOptionsFromEntities(userEntities, {}, 'creator_id', 'admin'))).toEqual(['me', 'Admin']);
    });

    it('keeps the options of a list nobody searches alphabetical (markings, enums, cached creators...)', () => {
      const entities = {
        objectMarking: [
          { label: 'TLP:GREEN', value: 'm1', type: 'Marking-Definition' },
          { label: 'TLP:AMBER', value: 'm2', type: 'Marking-Definition' },
          { label: 'PAP:GREEN', value: 'm3', type: 'Marking-Definition' },
        ] as FilterOptionValue[],
      };
      expect(labels(getOptionsFromEntities(entities, {}, 'objectMarking', 'green'))).toEqual(['PAP:GREEN', 'TLP:AMBER', 'TLP:GREEN']);
    });

    it('puts the ranked options first, in the order of the search, then the others alphabetically', () => {
      const entities = {
        objectMeta: [
          { label: 'TLP:RED', value: 'm1', type: 'Marking-Definition' },
          { label: 'red team', value: 'l1', type: 'Label', ranked: true },
          { label: 'PAP:RED', value: 'm2', type: 'Marking-Definition' },
          { label: 'red', value: 'l2', type: 'Label', ranked: true },
        ] as FilterOptionValue[],
      };
      expect(labels(getOptionsFromEntities(entities, {}, 'objectMeta', 'red'))).toEqual(['red team', 'red', 'PAP:RED', 'TLP:RED']);
    });

    it('orders the groups without any ranked option alphabetically, after the groups with ranked options', () => {
      const entities = {
        objectMeta: [
          { label: 'Zulu', value: 'z', type: 'Vocabulary', group: 'Zone' },
          { label: 'Alpha', value: 'a', type: 'Vocabulary', group: 'Area' },
          { label: 'Lazarus', value: 'l', type: 'Malware', group: 'Malware', ranked: true },
        ] as FilterOptionValue[],
      };
      expect(labels(getOptionsFromEntities(entities, {}, 'objectMeta', 'a'))).toEqual(['Lazarus', 'Alpha', 'Zulu']);
    });
  });

  it('ranks a searched user ahead of a built-in account matching the same term', () => {
    const data = {
      members: { edges: [{ node: { id: 'u1', entity_type: 'User', name: 'Rule' } }] },
      systemMembers: { edges: [{ node: { id: 's1', entity_type: 'User', name: 'RULE MANAGER' } }] },
    };
    const entities = { members_user: buildMembersOptions(data, ['User'], { searchTerm: 'rule' }) };
    expect(labels(getOptionsFromEntities(entities, {}, 'members_user', 'rule'))).toEqual(['Rule', 'RULE MANAGER']);
  });

  describe('buildMembersOptions', () => {
    const data = {
      members: { edges: [{ node: { id: 'g1', entity_type: 'Group', name: 'Analysts' } }] },
      systemMembers: { edges: [{ node: { id: 's1', entity_type: 'User', name: 'SYSTEM' } }] },
    };

    it('only adds the built-in accounts and @me when the filter targets users', () => {
      expect(labels(buildMembersOptions(data, ['Group'], { meOption: { label: 'me', value: ME_FILTER_VALUE, type: 'User' } }))).toEqual(['Analysts']);
    });

    it('puts @me first, then the searched members, then the built-in accounts', () => {
      const me = { label: 'me', value: ME_FILTER_VALUE, type: 'User' };
      expect(labels(buildMembersOptions(data, ['User', 'Group'], { meOption: me }))).toEqual(['me', 'Analysts', 'SYSTEM']);
      expect(labels(buildMembersOptions(data, ['User', 'Group']))).toEqual(['Analysts', 'SYSTEM']);
    });

    it('only ranks the searched members, and only when a term is typed', () => {
      const ranks = (options: FilterOptionValue[]) => options.map((o) => !!o.ranked);
      expect(ranks(buildMembersOptions(data, ['User', 'Group'], { searchTerm: 'a' }))).toEqual([true, false]);
      expect(ranks(buildMembersOptions(data, ['User', 'Group'], { searchTerm: ' ' }))).toEqual([false, false]);
    });
  });

  describe('rankOptions', () => {
    const options: FilterOptionValue[] = [{ label: 'red', value: 'l1', type: 'Label' }];

    it('ranks the options of a search for a typed term', () => {
      expect(rankOptions(options, 'red')).toEqual([{ label: 'red', value: 'l1', type: 'Label', ranked: true }]);
    });

    it('does not rank the options of a search without a term', () => {
      expect(rankOptions(options, '')).toEqual(options);
      expect(rankOptions(options, '   ')).toEqual(options);
    });
  });

  it('only keeps the entities of the search scope', () => {
    const entities = {
      id: [entity('Zeus', 'Malware'), entity('APT28', 'Intrusion-Set')],
    };
    expect(labels(getOptionsFromEntities(entities, { id: ['Malware'] }, 'id'))).toEqual(['Zeus']);
  });
});
