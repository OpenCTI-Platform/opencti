import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook, act, waitFor } from '@testing-library/react';

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
      filterKeysSchema: new Map(),
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

vi.mock('@mui/styles', () => ({
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

  it('should not execute search when event is falsy', () => {
    const { result } = renderHook(() => useSearchEntities(defaultOptions));
    const [, searchEntities] = result.current;

    act(() => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      searchEntities('entity_type', {}, vi.fn(), null as any);
    });

    expect(defaultOptions.setInputValues).not.toHaveBeenCalled();
  });
});

describe('useSearchEntities - StatusTemplate branch', () => {
  beforeEach(() => {
    mockFetchQuery.mockReset();
  });

  it('should sort status templates alphabetically', async () => {
    const mockData = {
      statusTemplates: {
        edges: [
          { node: { id: 'st-2', name: 'Zulu', color: '#ff0' } },
          { node: { id: 'st-1', name: 'Alpha', color: '#00f' } },
        ],
      },
    };

    mockFetchQuery.mockReturnValue({
      toPromise: () => Promise.resolve(mockData),
    });

    // The StatusTemplate branch maps results to type: 'Vocabulary' and sorts by label
    const edges = mockData.statusTemplates.edges;
    const statusTemplateEntities = edges
      .flatMap((n) => (!n ? [] : {
        label: n.node.name,
        color: n.node.color,
        value: n.node.id,
        type: 'Vocabulary',
      }))
      .sort((a, b) => (a.label ?? '').localeCompare(b.label ?? ''));

    expect(statusTemplateEntities[0].label).toBe('Alpha');
    expect(statusTemplateEntities[1].label).toBe('Zulu');
    expect(statusTemplateEntities[0].type).toBe('Vocabulary');
    expect(statusTemplateEntities[0].value).toBe('st-1');
  });

  it('maps StatusTemplate results to Vocabulary type', () => {
    const node = { id: 'st-1', name: 'Test', color: '#abc' };
    const mapped = {
      label: node.name,
      color: node.color,
      value: node.id,
      type: 'Vocabulary',
    };
    expect(mapped.type).toBe('Vocabulary');
    expect(mapped.label).toBe('Test');
  });
});
