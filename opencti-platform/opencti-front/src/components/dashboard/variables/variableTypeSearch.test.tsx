import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type React from 'react';

// Key list checked against the generated back schema by opencti-graphql/tests/03-integration/01-database/filterKeysSchema-test.ts,
// read as text: the file is outside the front TypeScript project.
const stixCoreObjectFilterKeysSource = readFileSync(
  resolve(dirname(fileURLToPath(import.meta.url)), '../../../../../opencti-graphql/tests/data/filter-keys-schema/stix-core-object.ts'),
  'utf8',
);
const stixCoreObjectFilterKeys = Array.from(stixCoreObjectFilterKeysSource.matchAll(/^\s+'([^']+)',?$/gm), (match) => match[1]);

const mockFetchQuery = vi.fn();

vi.mock('../../../relay/environment', () => ({
  fetchQuery: (...args: unknown[]) => mockFetchQuery(...args),
  MESSAGING$: { messages$: { subscribe: vi.fn() } },
}));

// Definitions copied from opencti-graphql/src/domain/filterKeysSchema.ts for the keys searched through the schema.
vi.mock('../../../utils/hooks/useAuth', () => ({
  default: () => ({
    me: {
      id: 'user-1',
      name: 'Test User',
      allowed_marking: [{ id: 'marking-1', definition_type: 'TLP', definition: 'TLP:GREEN', x_opencti_order: 1, x_opencti_color: '#2e7d32' }],
    },
    schema: {
      scos: [{ id: 'IPv4-Addr', label: 'IPv4-Addr' }],
      sdos: [{ id: 'Malware', label: 'Malware' }],
      scrs: [{ id: 'targets', label: 'targets' }],
      smos: [{ id: 'Label' }, { id: 'Marking-Definition' }, { id: 'Kill-Chain-Phase' }, { id: 'External-Reference' }],
      filterKeysSchema: new Map([
        ['Stix-Core-Object', new Map([
          ['objectLabel', { filterKey: 'objectLabel', type: 'id', elementsForFilterValuesSearch: ['Label'] }],
          ['objectMarking', { filterKey: 'objectMarking', type: 'id', elementsForFilterValuesSearch: ['Marking-Definition'] }],
          ['workflow_id', { filterKey: 'workflow_id', type: 'id', elementsForFilterValuesSearch: ['StatusTemplate'] }],
          ['killChainPhases', { filterKey: 'killChainPhases', type: 'id', elementsForFilterValuesSearch: ['Kill-Chain-Phase'] }],
        ])],
      ]),
    },
  }),
}));

vi.mock('../../i18n', () => ({ useFormatter: () => ({ t_i18n: (key: string) => key }) }));

vi.mock('../../../utils/hooks/useAttributes', () => ({
  default: () => ({ stixCoreObjectTypes: ['Malware', 'Sector', 'IPv4-Addr'] }),
  containerTypes: ['Report'],
}));

vi.mock('@mui/styles', () => ({ useTheme: () => ({ palette: { mode: 'light', primary: { main: '#1976d2' } } }) }));

vi.mock('../../../utils/hooks/useGranted', () => ({
  default: () => false,
  SETTINGS_SETACCESSES: 'SETTINGS_SETACCESSES',
  VIRTUAL_ORGANIZATION_ADMIN: 'VIRTUAL_ORGANIZATION_ADMIN',
}));

vi.mock('../../../utils/edition', () => ({
  convertMarking: (m: { id: string; definition: string }) => ({ label: m.definition, value: m.id }),
}));

vi.mock('@components/common/identities/IdentitySearch', () => ({
  identitySearchCreatorsSearchQuery: 'identitySearchCreatorsSearchQuery',
  identitySearchIdentitiesSearchQuery: 'identitySearchIdentitiesSearchQuery',
}));
vi.mock('@components/common/stix_domain_objects/StixDomainObjectsLines', () => ({ stixDomainObjectsLinesSearchQuery: 'stixDomainObjectsLinesSearchQuery' }));
vi.mock('@components/settings/LabelsQuery', () => ({ labelsSearchQuery: 'labelsSearchQuery' }));
vi.mock('@components/settings/VocabularyQuery', () => ({ vocabularySearchQuery: 'vocabularySearchQuery' }));
vi.mock('@components/common/form/ObjectAssigneeField', () => ({
  objectAssigneeFieldAssigneesSearchQuery: 'objectAssigneeFieldAssigneesSearchQuery',
  objectAssigneeFieldMembersSearchQuery: 'objectAssigneeFieldMembersSearchQuery',
}));
vi.mock('@components/common/form/ObjectParticipantField', () => ({ objectParticipantFieldParticipantsSearchQuery: 'objectParticipantFieldParticipantsSearchQuery' }));
vi.mock('@components/common/form/StatusTemplateField', () => ({ StatusTemplateFieldQuery: 'StatusTemplateFieldQuery' }));
vi.mock('@components/analyses/external_references/ExternalReferencesQueries', () => ({ externalReferencesQueriesSearchQuery: 'externalReferencesQueriesSearchQuery' }));
vi.mock('@components/common/form/NotifierField', () => ({ NotifierFieldQuery: 'NotifierFieldQuery' }));
vi.mock('@components/settings/KillChainPhases', () => ({ killChainPhasesSearchQuery: 'killChainPhasesSearchQuery' }));
vi.mock('@components/profile/triggers/TriggersQueries', () => ({ triggersQueriesSearchQuery: 'triggersQueriesSearchQuery' }));
vi.mock('@components/data/DataTableToolBar', () => ({ toolBarUsersLinesSearchQuery: 'toolBarUsersLinesSearchQuery' }));

import useSearchEntities from '../../../utils/filters/useSearchEntities';
import { VARIABLE_TYPE_SEARCH, VARIABLE_SEARCH_CONTEXT } from './variableTypeSearch';
import type { DashboardVariableType } from '../dashboard-types';

const searchWith = (type: DashboardVariableType, searchScope: Record<string, string[]> = {}) => {
  const key = VARIABLE_TYPE_SEARCH[type] as string;
  const { result } = renderHook(() => useSearchEntities({ searchContext: VARIABLE_SEARCH_CONTEXT, searchScope, setInputValues: vi.fn() }));
  act(() => {
    result.current[1](key, {}, vi.fn(), { target: { value: '' } } as unknown as React.BaseSyntheticEvent);
  });
  return { key, entities: () => result.current[0][key] ?? [] };
};

describe('VARIABLE_TYPE_SEARCH', () => {
  beforeEach(() => {
    mockFetchQuery.mockReset();
    mockFetchQuery.mockReturnValue({ toPromise: () => new Promise(() => {}) });
  });

  it('reads the back key list', () => {
    expect(stixCoreObjectFilterKeys).toEqual(expect.arrayContaining(['entity_type', 'creator_id', 'createdBy']));
  });

  it.each(['label', 'marking', 'status'] as const)('searches %s through a Stix-Core-Object filter key of the back schema', (type) => {
    expect(stixCoreObjectFilterKeys).toContain(VARIABLE_TYPE_SEARCH[type]);
  });

  it('searches labels with the labels query', () => {
    searchWith('label');
    expect(mockFetchQuery).toHaveBeenCalledWith('labelsSearchQuery', expect.anything());
  });

  it('lists the markings the user is allowed to see', () => {
    const { entities } = searchWith('marking');
    expect(entities().map((o) => o.value)).toEqual(['marking-1']);
  });

  it('searches statuses with the status templates query', () => {
    searchWith('status');
    expect(mockFetchQuery).toHaveBeenCalledWith('StatusTemplateFieldQuery', expect.anything());
  });

  it.each([['user', 'User'], ['group', 'Group']] as const)('searches %s among all the platform members', (type, memberType) => {
    searchWith(type);
    expect(mockFetchQuery).toHaveBeenCalledWith('objectAssigneeFieldMembersSearchQuery', expect.objectContaining({ entityTypes: [memberType] }));
  });

  it('searches entities of the variable entity types', () => {
    searchWith('entity', { [VARIABLE_TYPE_SEARCH.entity as string]: ['Sector'] });
    expect(mockFetchQuery).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ types: ['Sector'] }));
  });

  it('lists the entity types of the schema', () => {
    const { entities } = searchWith('entityType');
    expect(mockFetchQuery).not.toHaveBeenCalled();
    expect(entities().map((o) => o.value)).toEqual(expect.arrayContaining(['Malware', 'IPv4-Addr']));
  });
});
