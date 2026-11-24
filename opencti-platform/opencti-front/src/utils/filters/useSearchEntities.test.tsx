import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook, act, waitFor } from '@testing-library/react';
import type React from 'react';

const mockFetchQuery = vi.fn();

vi.mock('../../relay/environment', () => ({
  fetchQuery: (...args: unknown[]) => mockFetchQuery(...args),
  MESSAGING$: { messages$: { subscribe: vi.fn() } },
}));

vi.mock('../hooks/useAuth', () => ({
  default: () => ({
    me: {
      id: 'user-1',
      name: 'Test User',
      allowed_marking: [
        { id: 'marking-1', definition_type: 'TLP', definition: 'TLP:GREEN', x_opencti_order: 1, x_opencti_color: '#2e7d32' },
        { id: 'marking-2', definition_type: 'TLP', definition: 'TLP:AMBER', x_opencti_order: 2, x_opencti_color: '#d84315' },
      ],
    },
    schema: {
      scos: [
        { id: 'IPv4-Addr', label: 'IPv4-Addr' },
        { id: 'Domain-Name', label: 'Domain-Name' },
      ],
      sdos: [
        { id: 'Malware', label: 'Malware' },
        { id: 'Campaign', label: 'Campaign' },
      ],
      scrs: [
        { id: 'targets', label: 'targets' },
        { id: 'uses', label: 'uses' },
      ],
      smos: [
        { id: 'Label' },
        { id: 'Marking-Definition' },
        { id: 'Kill-Chain-Phase' },
        { id: 'External-Reference' },
      ],
      filterKeysSchema: new Map([
        ['Stix-Core-Object', new Map([
          ['status_id', { type: 'id', elementsForFilterValuesSearch: ['StatusTemplate'] }],
          ['objectLabel', { type: 'id', elementsForFilterValuesSearch: ['Label'] }],
          ['objectMarking', { type: 'id', elementsForFilterValuesSearch: ['Marking-Definition'] }],
        ])],
      ]),
    },
  }),
}));

vi.mock('../../components/i18n', () => ({
  useFormatter: () => ({
    t_i18n: (key: string) => key,
  }),
}));

vi.mock('../hooks/useAttributes', () => ({
  default: () => ({
    stixCoreObjectTypes: ['Malware', 'Campaign', 'IPv4-Addr', 'Domain-Name'],
  }),
  containerTypes: ['Report', 'Grouping', 'Note', 'Opinion', 'Observed-Data'],
}));

vi.mock('@mui/material/styles', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@mui/material/styles')>()),
  useTheme: () => ({
    palette: {
      mode: 'light',
      primary: { main: '#1976d2' },
    },
  }),
}));

vi.mock('../hooks/useGranted', () => ({
  default: () => false,
  SETTINGS_SETACCESSES: 'SETTINGS_SETACCESSES',
  VIRTUAL_ORGANIZATION_ADMIN: 'VIRTUAL_ORGANIZATION_ADMIN',
}));

vi.mock('../edition', () => ({
  convertMarking: (m: { id: string; definition: string; x_opencti_color: string }) => ({
    label: m.definition,
    value: m.id,
    color: m.x_opencti_color,
  }),
}));

vi.mock('@components/common/identities/IdentitySearch', () => ({
  identitySearchCreatorsSearchQuery: 'identitySearchCreatorsSearchQuery',
  identitySearchIdentitiesSearchQuery: 'identitySearchIdentitiesSearchQuery',
}));

vi.mock('@components/common/stix_domain_objects/StixDomainObjectsLines', () => ({
  stixDomainObjectsLinesSearchQuery: 'stixDomainObjectsLinesSearchQuery',
}));

vi.mock('@components/settings/LabelsQuery', () => ({
  labelsSearchQuery: 'labelsSearchQuery',
}));

vi.mock('@components/settings/VocabularyQuery', () => ({
  vocabularySearchQuery: 'vocabularySearchQuery',
}));

vi.mock('@components/common/form/ObjectAssigneeField', () => ({
  objectAssigneeFieldAssigneesSearchQuery: 'objectAssigneeFieldAssigneesSearchQuery',
  objectAssigneeFieldMembersSearchQuery: 'objectAssigneeFieldMembersSearchQuery',
}));

vi.mock('@components/common/form/ObjectParticipantField', () => ({
  objectParticipantFieldParticipantsSearchQuery: 'objectParticipantFieldParticipantsSearchQuery',
}));

vi.mock('@components/common/form/StatusTemplateField', () => ({
  StatusTemplateFieldQuery: 'StatusTemplateFieldQuery',
}));

vi.mock('@components/analyses/external_references/ExternalReferencesQueries', () => ({
  externalReferencesQueriesSearchQuery: 'externalReferencesQueriesSearchQuery',
}));

vi.mock('@components/common/form/NotifierField', () => ({
  NotifierFieldQuery: 'NotifierFieldQuery',
}));

vi.mock('@components/settings/KillChainPhases', () => ({
  killChainPhasesSearchQuery: 'killChainPhasesSearchQuery',
}));

vi.mock('@components/profile/triggers/TriggersQueries', () => ({
  triggersQueriesSearchQuery: 'triggersQueriesSearchQuery',
}));

vi.mock('@components/data/DataTableToolBar', () => ({
  toolBarUsersLinesSearchQuery: 'toolBarUsersLinesSearchQuery',
}));

import useSearchEntities from './useSearchEntities';
import { ME_FILTER_VALUE } from './filtersUtils';

const createEvent = (value: string) => ({
  target: { value },
}) as unknown as React.BaseSyntheticEvent;

describe('useSearchEntities', () => {
  const defaultOptions = {
    availableEntityTypes: undefined,
    availableRelationshipTypes: undefined,
    searchContext: { entityTypes: ['Stix-Core-Object'] } as { entityTypes: string[]; elementType?: string },
    searchScope: {} as Record<string, string[]>,
    setInputValues: vi.fn(),
  };

  beforeEach(() => {
    mockFetchQuery.mockReset();
    defaultOptions.setInputValues.mockClear();
  });

  it('should initialize with empty entities', () => {
    const { result } = renderHook(() => useSearchEntities(defaultOptions));
    const [entities] = result.current;
    expect(entities).toEqual({});
  });

  it('should call setInputValues when searchEntities is triggered', () => {
    const { result } = renderHook(() => useSearchEntities(defaultOptions));
    const [, searchEntities] = result.current;

    act(() => {
      searchEntities('objectMarking', {}, vi.fn(), createEvent('test'));
    });

    expect(defaultOptions.setInputValues).toHaveBeenCalledWith([
      { key: 'objectMarking', values: ['test'], operator: 'eq' },
    ]);
  });

  it('should populate entity_type with SDOs, SCOs, and relationships', () => {
    const { result } = renderHook(() => useSearchEntities(defaultOptions));
    const [, searchEntities] = result.current;

    act(() => {
      searchEntities('entity_type', {}, vi.fn(), createEvent(''));
    });

    const [entities] = result.current;
    const entityTypeOptions = entities.entity_type ?? [];
    // Should contain SCOs, SDOs, relationships, and abstract types
    expect(entityTypeOptions.length).toBeGreaterThan(0);
    expect(entityTypeOptions.some((e) => e.value === 'Malware')).toBe(true);
    expect(entityTypeOptions.some((e) => e.value === 'IPv4-Addr')).toBe(true);
    expect(entityTypeOptions.some((e) => e.value === 'targets')).toBe(true);
    expect(entityTypeOptions.some((e) => e.value === 'Stix-Cyber-Observable')).toBe(true);
    expect(entityTypeOptions.some((e) => e.value === 'Stix-Domain-Object')).toBe(true);
  });

  it('should populate entity_type with only specified availableEntityTypes', () => {
    const options = {
      ...defaultOptions,
      availableEntityTypes: ['Malware', 'Campaign'],
    };
    const { result } = renderHook(() => useSearchEntities(options));
    const [, searchEntities] = result.current;

    act(() => {
      searchEntities('entity_type', {}, vi.fn(), createEvent(''));
    });

    const [entities] = result.current;
    const entityTypeOptions = entities.entity_type ?? [];
    expect(entityTypeOptions).toHaveLength(2);
    expect(entityTypeOptions.some((e) => e.value === 'Malware')).toBe(true);
    expect(entityTypeOptions.some((e) => e.value === 'Campaign')).toBe(true);
  });

  it('should populate toTypes with the observables, domain objects and relationships', () => {
    const { result } = renderHook(() => useSearchEntities(defaultOptions));
    const [, searchEntities] = result.current;

    act(() => {
      searchEntities('toTypes', {}, vi.fn(), createEvent(''));
    });

    const toTypesValues = (result.current[0].toTypes ?? []).map((e) => e.value);
    expect(toTypesValues).toEqual(expect.arrayContaining(['Malware', 'IPv4-Addr', 'targets', 'Stix-Domain-Object']));
  });

  it('should populate toTypes with only the types of its search scope', () => {
    const options = { ...defaultOptions, searchScope: { toTypes: ['Vulnerability', 'Attack-Pattern'] } };
    const { result } = renderHook(() => useSearchEntities(options));
    const [, searchEntities] = result.current;

    act(() => {
      searchEntities('toTypes', {}, vi.fn(), createEvent(''));
    });

    expect((result.current[0].toTypes ?? []).map((e) => e.value)).toEqual(['Attack-Pattern', 'Vulnerability']);
  });

  it('should search the entities of a key with the search filters of this key only', () => {
    mockFetchQuery.mockReturnValue({ toPromise: () => Promise.resolve({ stixCoreObjects: { edges: [] } }) });
    const connectedFilters = { mode: 'and', filterGroups: [], filters: [{ key: ['id'], values: ['result-1'] }] };
    const options = { ...defaultOptions, searchContext: { entityTypes: ['Stix-Core-Object'], searchFilters: { connectedToId: connectedFilters } } };
    const { result } = renderHook(() => useSearchEntities(options as typeof defaultOptions));
    const [, searchEntities] = result.current;

    act(() => {
      searchEntities('connectedToId', {}, vi.fn(), createEvent('alpha'));
    });
    expect(mockFetchQuery).toHaveBeenLastCalledWith(expect.anything(), expect.objectContaining({ search: 'alpha', filters: connectedFilters }));

    // another key has no search filters: its search is not restricted
    mockFetchQuery.mockClear();
    act(() => {
      searchEntities('id', {}, vi.fn(), createEvent('alpha'));
    });
    expect(mockFetchQuery).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ search: 'alpha', filters: undefined }));
  });

  it('should populate markings from user allowed_marking', () => {
    const { result } = renderHook(() => useSearchEntities(defaultOptions));
    const [, searchEntities] = result.current;

    act(() => {
      searchEntities('objectMarking', {}, vi.fn(), createEvent(''));
    });

    const [entities] = result.current;
    const markingOptions = entities.objectMarking ?? [];
    expect(markingOptions).toHaveLength(2);
    expect(markingOptions.some((e) => e.value === 'marking-1')).toBe(true);
    expect(markingOptions.some((e) => e.value === 'marking-2')).toBe(true);
  });

  it('should fetch labels via fetchQuery', async () => {
    const mockLabelsData = {
      labels: {
        edges: [
          { node: { id: 'label-1', value: 'phishing', color: '#ff0000' } },
          { node: { id: 'label-2', value: 'malware', color: '#00ff00' } },
        ],
      },
    };
    mockFetchQuery.mockReturnValue({ toPromise: () => Promise.resolve(mockLabelsData) });

    const { result } = renderHook(() => useSearchEntities(defaultOptions));
    const [, searchEntities] = result.current;

    act(() => {
      searchEntities('objectLabel', {}, vi.fn(), createEvent('ph'));
    });

    await waitFor(() => {
      const [entities] = result.current;
      const labelOptions = entities.objectLabel ?? [];
      expect(labelOptions.length).toBeGreaterThan(0);
    });

    const [entities] = result.current;
    const labelOptions = entities.objectLabel ?? [];
    // Should include the "No label" entry + fetched labels
    expect(labelOptions.some((e) => e.value === null)).toBe(true);
    expect(labelOptions.some((e) => e.value === 'label-1')).toBe(true);
    expect(labelOptions.some((e) => e.value === 'label-2')).toBe(true);
    // the searched labels are ranked by relevance, "No label" is not searched
    expect(labelOptions.filter((e) => e.ranked).map((e) => e.value)).toEqual(['label-1', 'label-2']);
  });

  it('should not rank the labels of a search without a term', async () => {
    const mockLabelsData = { labels: { edges: [{ node: { id: 'label-1', value: 'phishing', color: '#ff0000' } }] } };
    mockFetchQuery.mockReturnValue({ toPromise: () => Promise.resolve(mockLabelsData) });
    const { result } = renderHook(() => useSearchEntities(defaultOptions));
    const [, searchEntities] = result.current;

    act(() => {
      searchEntities('objectLabel', {}, vi.fn(), createEvent(''));
    });

    await waitFor(() => {
      expect(result.current[0].objectLabel?.some((e) => e.value === 'label-1')).toBe(true);
    });
    expect(result.current[0].objectLabel?.some((e) => e.ranked)).toBe(false);
  });

  it('should not rank the markings, which are not searched', () => {
    const { result } = renderHook(() => useSearchEntities(defaultOptions));
    const [, searchEntities] = result.current;

    act(() => {
      searchEntities('objectMarking', {}, vi.fn(), createEvent('tlp'));
    });

    const markingOptions = result.current[0].objectMarking ?? [];
    expect(markingOptions).toHaveLength(2);
    expect(markingOptions.some((e) => e.ranked)).toBe(false);
  });

  it('should rank the searched members, after @me and ahead of the unsearched built-in accounts', async () => {
    mockFetchQuery.mockReturnValue({
      toPromise: () => Promise.resolve({
        members: { edges: [{ node: { id: 'user-2', entity_type: 'User', name: 'Rule' } }] },
        systemMembers: { edges: [{ node: { id: 'system-1', entity_type: 'User', name: 'RULE MANAGER' } }] },
      }),
    });
    const { result } = renderHook(() => useSearchEntities(defaultOptions));
    const [, searchEntities] = result.current;

    act(() => {
      searchEntities('members_user', {}, vi.fn(), createEvent('rule'));
    });

    await waitFor(() => {
      expect(result.current[0].members_user).toBeDefined();
    });
    expect(mockFetchQuery).toHaveBeenCalledWith(
      'objectAssigneeFieldMembersSearchQuery',
      expect.objectContaining({ search: 'rule', entityTypes: ['User'] }),
    );
    expect(result.current[0].members_user?.map(({ value, ranked }) => ({ value, ranked: !!ranked }))).toEqual([
      { value: ME_FILTER_VALUE, ranked: false },
      { value: 'user-2', ranked: true },
      { value: 'system-1', ranked: false },
    ]);
  });

  it('should order the searched vocabularies by relevance, not by their configured order', () => {
    mockFetchQuery.mockReturnValue({ toPromise: () => Promise.resolve({ vocabularies: { edges: [] } }) });
    const { result } = renderHook(() => useSearchEntities(defaultOptions));
    const [, searchEntities] = result.current;

    act(() => {
      searchEntities('computed_reliability', {}, vi.fn(), createEvent('reliable'));
    });

    expect(mockFetchQuery).toHaveBeenCalledWith(
      'vocabularySearchQuery',
      expect.objectContaining({ search: 'reliable', orderBy: '_score', orderMode: 'desc' }),
    );
  });

  it('should keep the default vocabulary order when no term is typed', () => {
    mockFetchQuery.mockReturnValue({ toPromise: () => Promise.resolve({ vocabularies: { edges: [] } }) });
    const { result } = renderHook(() => useSearchEntities(defaultOptions));
    const [, searchEntities] = result.current;

    act(() => {
      searchEntities('computed_reliability', {}, vi.fn(), createEvent(''));
    });

    const variables = mockFetchQuery.mock.calls.find(([query]) => query === 'vocabularySearchQuery')?.[1];
    expect(variables).toBeDefined();
    expect(variables).not.toHaveProperty('orderBy');
    expect(variables).not.toHaveProperty('orderMode');
  });

  it('should fetch stix core objects for id filter', async () => {
    const mockData = {
      stixCoreObjects: {
        edges: [
          {
            node: {
              id: 'obj-1',
              entity_type: 'Malware',
              parent_types: ['Stix-Domain-Object', 'Stix-Core-Object'],
              name: 'WannaCry',
              representative: { main: 'WannaCry' },
            },
          },
        ],
      },
    };
    mockFetchQuery.mockReturnValue({ toPromise: () => Promise.resolve(mockData) });

    const { result } = renderHook(() => useSearchEntities(defaultOptions));
    const [, searchEntities] = result.current;

    act(() => {
      searchEntities('id', {}, vi.fn(), createEvent('wanna'));
    });

    await waitFor(() => {
      const [entities] = result.current;
      expect((entities.id ?? []).length).toBeGreaterThan(0);
    });

    const [entities] = result.current;
    const idOptions = entities.id ?? [];
    expect(idOptions.some((e) => e.value === 'obj-1')).toBe(true);
  });

  it('should ignore the answer to an older search of the same key, which would replace the latest relevance order', async () => {
    // each query answers when the test resolves it, in the order the test chooses
    const answers: Array<(data: unknown) => void> = [];
    mockFetchQuery.mockImplementation(() => ({
      toPromise: () => new Promise((resolve) => {
        answers.push(resolve);
      }),
    }));
    const labelsAnswer = (...names: string[]) => ({
      labels: { edges: names.map((name) => ({ node: { id: name, value: name, color: '#000000' } })) },
    });
    const { result } = renderHook(() => useSearchEntities(defaultOptions));

    act(() => {
      result.current[1]('objectLabel', {}, vi.fn(), createEvent('sc'));
    });
    act(() => {
      result.current[1]('objectLabel', {}, vi.fn(), createEvent('scr'));
    });
    // the answer to "scr" comes back first, then the one to "sc"
    await act(async () => answers[1](labelsAnswer('SCR test')));
    await act(async () => answers[0](labelsAnswer('scan', 'SCR test')));

    expect(result.current[0].objectLabel?.map((e) => e.value)).toEqual([null, 'SCR test']);
  });

  it('should keep the answers of all the sources queried by the latest search of a key', async () => {
    mockFetchQuery.mockImplementation((query: string) => ({
      toPromise: () => Promise.resolve(query === 'objectAssigneeFieldMembersSearchQuery'
        ? { members: { edges: [{ node: { id: 'user-2', entity_type: 'User', name: 'Scr user' } }] }, systemMembers: { edges: [] } }
        : { stixCoreObjects: { edges: [{ node: {
            id: 'obj-1',
            entity_type: 'Malware',
            parent_types: ['Stix-Domain-Object', 'Stix-Core-Object'],
            name: 'Scr malware',
            representative: { main: 'Scr malware' },
          } }] } }),
    }));
    const { result } = renderHook(() => useSearchEntities(defaultOptions));

    act(() => {
      result.current[1]('contextEntityId', {}, vi.fn(), createEvent('scr'));
    });

    await waitFor(() => {
      const values = (result.current[0].contextEntityId ?? []).map((e) => e.value);
      expect(values).toEqual(expect.arrayContaining(['obj-1', 'user-2']));
    });
  });

  it('should build relationship_type options from available types', () => {
    const options = {
      ...defaultOptions,
      availableRelationshipTypes: ['targets', 'uses'],
    };
    const { result } = renderHook(() => useSearchEntities(options));
    const [, searchEntities] = result.current;

    act(() => {
      searchEntities('relationship_type', {}, vi.fn(), createEvent(''));
    });

    const [entities] = result.current;
    const relOptions = entities.relationship_type ?? [];
    expect(relOptions).toHaveLength(2);
    expect(relOptions.some((e) => e.value === 'targets')).toBe(true);
    expect(relOptions.some((e) => e.value === 'uses')).toBe(true);
  });

  it('should include object-label relationship type when entityTypes include object-label', () => {
    const options = {
      ...defaultOptions,
      searchContext: { entityTypes: ['stix-core-relationship', 'object-label'] } as { entityTypes: string[]; elementType?: string },
    };
    const { result } = renderHook(() => useSearchEntities(options));
    const [, searchEntities] = result.current;

    act(() => {
      searchEntities('relationship_type', {}, vi.fn(), createEvent(''));
    });

    const [entities] = result.current;
    const relOptions = entities.relationship_type ?? [];
    expect(relOptions.some((e) => e.value === 'object-label')).toBe(true);
  });

  it('should include some ref relationship types in the relationship_type subfilter of regardingOf', () => {
    const { result } = renderHook(() => useSearchEntities(defaultOptions));
    const [, searchEntities] = result.current;

    act(() => {
      searchEntities('relationship_type', {}, vi.fn(), createEvent(''), 'regardingOf');
    });

    const [entities] = result.current;
    const relOptions = (entities.relationship_type ?? []).map((e) => e.value);
    expect(relOptions).toEqual(expect.arrayContaining(['object-label', 'external-reference', 'object-covered', 'result-of']));
  });

  it('should not include the marking ref relationship type in the relationship_type subfilter of regardingOf', () => {
    const { result } = renderHook(() => useSearchEntities(defaultOptions));
    const [, searchEntities] = result.current;

    act(() => {
      searchEntities('relationship_type', {}, vi.fn(), createEvent(''), 'regardingOf');
    });

    const [entities] = result.current;
    const relOptions = (entities.relationship_type ?? []).map((e) => e.value);
    expect(relOptions).not.toContain('object-marking');
  });

  it('should include the external-reference relationship type in the relationship_type subfilter of dynamicRegardingOf', () => {
    const { result } = renderHook(() => useSearchEntities(defaultOptions));
    const [, searchEntities] = result.current;

    act(() => {
      searchEntities('relationship_type', {}, vi.fn(), createEvent(''), 'dynamicRegardingOf');
    });

    const [entities] = result.current;
    const relOptions = (entities.relationship_type ?? []).map((e) => e.value);
    expect(relOptions).toEqual(expect.arrayContaining(['object-label', 'external-reference', 'object-covered', 'result-of']));
  });

  it('should fetch external references in the id subfilter of regardingOf', async () => {
    mockFetchQuery.mockImplementation((query: string) => ({
      toPromise: () => Promise.resolve(query === 'externalReferencesQueriesSearchQuery'
        ? { externalReferences: { edges: [{ node: { id: 'ext-ref-1', source_name: 'mitre-attack', external_id: 'T1059' } }] } }
        : { stixCoreObjects: { edges: [] } }),
    }));
    const { result } = renderHook(() => useSearchEntities(defaultOptions));
    const [, searchEntities] = result.current;

    act(() => {
      searchEntities('id', {}, vi.fn(), createEvent('mitre'), 'regardingOf');
    });

    await waitFor(() => {
      const [entities] = result.current;
      expect(entities.id ?? []).toEqual(expect.arrayContaining([
        expect.objectContaining({ value: 'ext-ref-1', label: 'mitre-attack (T1059)', type: 'External-Reference', group: 'entity_External-Reference' }),
      ]));
    });
  });

  it('should not fetch external references for an id filter outside regardingOf', () => {
    mockFetchQuery.mockReturnValue({ toPromise: () => Promise.resolve({ stixCoreObjects: { edges: [] } }) });
    const { result } = renderHook(() => useSearchEntities(defaultOptions));
    const [, searchEntities] = result.current;

    act(() => {
      searchEntities('id', {}, vi.fn(), createEvent(''));
    });

    const queries = mockFetchQuery.mock.calls.map(([query]) => query);
    expect(queries).not.toContain('externalReferencesQueriesSearchQuery');
  });

  it('should not include regardingOf-only ref relationship types in the relationship_type filter', () => {
    const options = {
      ...defaultOptions,
      searchContext: { entityTypes: ['stix-core-relationship', 'contains', 'object-label'] } as { entityTypes: string[]; elementType?: string },
    };
    const { result } = renderHook(() => useSearchEntities(options));
    const [, searchEntities] = result.current;

    act(() => {
      searchEntities('relationship_type', {}, vi.fn(), createEvent(''));
    });

    const [entities] = result.current;
    const relOptions = (entities.relationship_type ?? []).map((e) => e.value);
    expect(relOptions).toEqual(expect.arrayContaining(['object', 'object-label']));
    expect(relOptions).not.toContain('external-reference');
    expect(relOptions).not.toContain('object-covered');
    expect(relOptions).not.toContain('result-of');
  });

  it('should not execute search when event is falsy', () => {
    const { result } = renderHook(() => useSearchEntities(defaultOptions));
    const [, searchEntities] = result.current;

    act(() => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      searchEntities('entity_type', {}, vi.fn(), null as any);
    });

    expect(defaultOptions.setInputValues).not.toHaveBeenCalled();
  });

  it('should sort status templates alphabetically', async () => {
    const mockData = {
      statusTemplates: {
        edges: [
          { node: { id: 'st-2', name: 'Zulu', color: '#ff0' } },
          { node: { id: 'st-1', name: 'Alpha', color: '#00f' } },
          { node: { id: 'st-3', name: 'Mike', color: '#0f0' } },
        ],
      },
    };
    mockFetchQuery.mockReturnValue({ toPromise: () => Promise.resolve(mockData) });

    const { result } = renderHook(() => useSearchEntities(defaultOptions));
    const [, searchEntities] = result.current;

    act(() => {
      searchEntities('status_id', {}, vi.fn(), createEvent(''));
    });

    await waitFor(() => {
      const [entities] = result.current;
      expect((entities.status_id ?? []).length).toBeGreaterThan(0);
    });

    const [entities] = result.current;
    const statusOptions = entities.status_id ?? [];
    expect(statusOptions[0].label).toBe('Alpha');
    expect(statusOptions[1].label).toBe('Mike');
    expect(statusOptions[2].label).toBe('Zulu');
    expect(statusOptions.every((e) => e.type === 'Vocabulary')).toBe(true);
  });

  it('should map StatusTemplate results to Vocabulary type', async () => {
    const mockData = {
      statusTemplates: {
        edges: [
          { node: { id: 'st-1', name: 'In Progress', color: '#f39c12' } },
        ],
      },
    };
    mockFetchQuery.mockReturnValue({ toPromise: () => Promise.resolve(mockData) });

    const { result } = renderHook(() => useSearchEntities(defaultOptions));
    const [, searchEntities] = result.current;

    act(() => {
      searchEntities('status_id', {}, vi.fn(), createEvent(''));
    });

    await waitFor(() => {
      const [entities] = result.current;
      expect((entities.status_id ?? []).length).toBeGreaterThan(0);
    });

    const [entities] = result.current;
    const statusOptions = entities.status_id ?? [];
    expect(statusOptions[0]).toEqual({
      label: 'In Progress',
      color: '#f39c12',
      value: 'st-1',
      type: 'Vocabulary',
    });
  });
});
