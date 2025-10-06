import * as R from 'ramda';
import { BaseSyntheticEvent, Dispatch, useState } from 'react';
import { graphql } from 'react-relay';
import { identitySearchCreatorsSearchQuery, identitySearchIdentitiesSearchQuery } from '@components/common/identities/IdentitySearch';
import { stixDomainObjectsLinesSearchQuery } from '@components/common/stix_domain_objects/StixDomainObjectsLines';
import { labelsSearchQuery } from '@components/settings/LabelsQuery';
import { vocabularySearchQuery } from '@components/settings/VocabularyQuery';
import { objectAssigneeFieldAssigneesSearchQuery, objectAssigneeFieldMembersSearchQuery } from '@components/common/form/ObjectAssigneeField';
import { IdentitySearchIdentitiesSearchQuery$data } from '@components/common/identities/__generated__/IdentitySearchIdentitiesSearchQuery.graphql';
import { IdentitySearchCreatorsSearchQuery$data } from '@components/common/identities/__generated__/IdentitySearchCreatorsSearchQuery.graphql';
import { ObjectAssigneeFieldAssigneesSearchQuery$data } from '@components/common/form/__generated__/ObjectAssigneeFieldAssigneesSearchQuery.graphql';
import { StixDomainObjectsLinesSearchQuery$data } from '@components/common/stix_domain_objects/__generated__/StixDomainObjectsLinesSearchQuery.graphql';
import { LabelsQuerySearchQuery$data } from '@components/settings/__generated__/LabelsQuerySearchQuery.graphql';
import { VocabularyQuery$data } from '@components/settings/__generated__/VocabularyQuery.graphql';
import { ObjectAssigneeFieldMembersSearchQuery$data } from '@components/common/form/__generated__/ObjectAssigneeFieldMembersSearchQuery.graphql';
import { ObjectParticipantFieldParticipantsSearchQuery$data } from '@components/common/form/__generated__/ObjectParticipantFieldParticipantsSearchQuery.graphql';
import { objectParticipantFieldParticipantsSearchQuery } from '@components/common/form/ObjectParticipantField';
import { useTheme } from '@mui/styles';
import { StatusTemplateFieldQuery } from '@components/common/form/StatusTemplateField';
import { StatusTemplateFieldSearchQuery$data } from '@components/common/form/__generated__/StatusTemplateFieldSearchQuery.graphql';
import { externalReferencesQueriesSearchQuery } from '@components/analyses/external_references/ExternalReferencesQueries';
import { ExternalReferencesQueriesSearchQuery$data } from '@components/analyses/external_references/__generated__/ExternalReferencesQueriesSearchQuery.graphql';
import { NotifierFieldQuery } from '@components/common/form/NotifierField';
import { NotifierFieldSearchQuery$data } from '@components/common/form/__generated__/NotifierFieldSearchQuery.graphql';
import { killChainPhasesSearchQuery } from '@components/settings/KillChainPhases';
import { KillChainPhasesSearchQuery$data } from '@components/settings/__generated__/KillChainPhasesSearchQuery.graphql';
import { triggersQueriesSearchQuery } from '@components/profile/triggers/TriggersQueries';
import { TriggersQueriesSearchQuery$data } from '@components/profile/triggers/__generated__/TriggersQueriesSearchQuery.graphql';
import { FilterOptionValue } from '@components/common/lists/FilterAutocomplete';
import { toolBarUsersLinesSearchQuery } from '@components/data/DataTableToolBar';
import { DataTableToolBarUsersLinesSearchQuery$data } from '@components/data/__generated__/DataTableToolBarUsersLinesSearchQuery.graphql';
import useAuth, { FilterDefinition } from '../hooks/useAuth';
import { useSearchEntitiesStixCoreObjectsSearchQuery$data } from './__generated__/useSearchEntitiesStixCoreObjectsSearchQuery.graphql';
import { useFormatter } from '../../components/i18n';
import { getMainRepresentative } from '../defaultRepresentatives';
import { fetchQuery } from '../../relay/environment';
import { useSearchEntitiesSchemaSCOSearchQuery$data } from './__generated__/useSearchEntitiesSchemaSCOSearchQuery.graphql';
import type { Theme } from '../../components/Theme';
import useAttributes, { containerTypes } from '../hooks/useAttributes';
import { contextFilters, entityTypesFilters, FilterSearchContext, getFilterDefinitionFromFilterKeysMap, ME_FILTER_VALUE } from './filtersUtils';
import { useSearchEntitiesDashboardsQuery$data } from './__generated__/useSearchEntitiesDashboardsQuery.graphql';
import { convertMarking } from '../edition';
import useGranted, { SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN } from '../hooks/useGranted';
import { displayEntityTypeForTranslation } from '../String';
import { useSearchEntitiesGroupsQuery$data } from './__generated__/useSearchEntitiesGroupsQuery.graphql';
import { useSearchEntitiesPirsQuery$data } from './__generated__/useSearchEntitiesPirsQuery.graphql';

const filtersStixCoreObjectsSearchQuery = graphql`
  query useSearchEntitiesStixCoreObjectsSearchQuery(
    $search: String
    $types: [String]
    $count: Int
    $filters: FilterGroup
  ) {
    stixCoreObjects(
      search: $search
      types: $types
      first: $count
      filters: $filters
    ) {
      edges {
        node {
          id
          entity_type
          parent_types
          ... on AttackPattern {
            name
            description
            x_mitre_id
          }
          ... on Note {
            attribute_abstract
            content
          }
          ... on ObservedData {
            name
            first_observed
            last_observed
          }
          ... on Opinion {
            opinion
          }
          ... on Report {
            name
          }
          ... on Grouping {
            name
          }
          ... on Campaign {
            name
            description
          }
          ... on CourseOfAction {
            name
            description
          }
          ... on Individual {
            name
            description
          }
          ... on Organization {
            name
            description
          }          
          ... on SecurityPlatform {
            name
            description
          }
          ... on Sector {
            name
            description
          }
          ... on System {
            name
            description
          }
          ... on Indicator {
            name
            description
          }
          ... on Infrastructure {
            name
            description
          }
          ... on IntrusionSet {
            name
            description
          }
          ... on Position {
            name
            description
          }
          ... on City {
            name
            description
          }
          ... on AdministrativeArea {
            name
            description
          }
          ... on Country {
            name
            description
          }
          ... on Region {
            name
            description
          }
          ... on Malware {
            name
            description
          }
          ... on MalwareAnalysis {
            product
            result_name
            operatingSystem {
              name
            }
          }
          ... on ThreatActor {
            name
            description
          }
          ... on Tool {
            name
            description
          }
          ... on Vulnerability {
            name
            description
          }
          ... on Incident {
            name
            description
          }
          ... on Event {
            name
            description
          }
          ... on Channel {
            name
            description
          }
          ... on Narrative {
            name
            description
          }
          ... on DataComponent {
            name
          }
          ... on DataSource {
            name
          }
          ... on Case {
            name
          }
          ... on Task {
            name
          }
          ... on Language {
            name
          }
          ... on StixCyberObservable {
            observable_value
          }
          createdBy {
            ... on Identity {
              id
              name
              entity_type
            }
          }
          objectMarking {
            id
            definition_type
            definition
            x_opencti_order
            x_opencti_color
          }
        }
      }
    }
  }
`;

const filtersSchemaSCOSearchQuery = graphql`
  query useSearchEntitiesSchemaSCOSearchQuery {
    schemaSCOs: subTypes(type: "Stix-Cyber-Observable") {
      edges {
        node {
          id
          label
        }
      }
    }
  }
`;

const workspacesQuery = graphql`
  query useSearchEntitiesDashboardsQuery($search: String, $filters: FilterGroup) {
    workspaces(search: $search, filters: $filters) {
      edges {
        node {
          id
          name
        }
      }
    }
  }
`;

const groupsQuery = graphql`
  query useSearchEntitiesGroupsQuery($search: String, $first: Int) {
    groups(search: $search, first: $first) {
      edges {
        node {
          id
          name
          entity_type
        }
      }
    }
  }
`;

const pirsQuery = graphql`
  query useSearchEntitiesPirsQuery($search: String, $first: Int) {
    pirs(search: $search, first: $first) {
      edges {
        node {
          id
          name
          entity_type
        }
      }
    }
  }
`;

export type EntityValue = FilterOptionValue;

const useSearchEntities = ({
  availableEntityTypes,
  availableRelationshipTypes,
  searchContext,
  searchScope,
  setInputValues,
}: {
  availableEntityTypes?: string[];
  availableRelationshipTypes?: string[];
  searchContext: FilterSearchContext;
  searchScope: Record<string, string[]>;
  setInputValues: (
    value: { key: string; values: string[]; operator?: string }[],
  ) => void;
}) => {
  const [entities, setEntities] = useState<Record<string, EntityValue[]>>({});
  const { t_i18n } = useFormatter();
  const { schema, me } = useAuth();
  const { stixCoreObjectTypes } = useAttributes();
  const theme = useTheme() as Theme;
  const canDisplayAllUsers = useGranted([SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN]);
  const filterKeysMap = new Map();
  (searchContext.entityTypes).forEach((entityType) => {
    const currentMap = schema.filterKeysSchema.get(entityType);
    currentMap?.forEach((value, key) => filterKeysMap.set(key, value));
  });
  const meEntity = {
    label: ME_FILTER_VALUE,
    value: ME_FILTER_VALUE,
    type: 'User',
    color: theme.palette.primary.main,
  };
  const unionSetEntities = (key: string, newEntities: EntityValue[]) => setEntities((c) => ({
    ...c,
    [key]: [...newEntities, ...(c[key] ?? [])].filter(
      ({ value, group }, index, arr) => arr.findIndex((v) => v.value === value && v.group === group)
        === index,
    ),
  }));

  const searchEntities = (
    filterKey: string,
    cacheEntities: Record< string, { label: string; value: string | null; type: string }[] >,
    setCacheEntities: Dispatch< Record<string, { label: string; value: string | null; type: string }[]> >,
    event: BaseSyntheticEvent,
    isSubKey?: boolean,
  ) => {
    if (!event) {
      return;
    }

    const newInputValue = {
      key: filterKey,
      values: event.target.value && event.target.value !== 0 ? [event.target.value?.toString()] : [],
      operator: 'eq',
    };
    setInputValues([newInputValue]);

    // fetches vocabularies by categories and add them to the set
    const buildOptionsFromVocabularySearchQuery = (key: string, filterCategories: string[]) => {
      const filters = {
        mode: 'or',
        filters: [
          { key: 'category', values: filterCategories, operator: 'eq', mode: 'or' },
        ],
        filterGroups: [],
      };
      fetchQuery(vocabularySearchQuery, {
        filters,
        search: event.target.value !== 0 ? event.target.value : '',
        first: 10,
      })
        .toPromise()
        .then((data) => {
          const entityValues = (
            ((data as VocabularyQuery$data)?.vocabularies?.edges ?? []).map((n) => ({
              label: n?.node.name,
              value: n?.node.name,
              type: 'Vocabulary',
            })));
          unionSetEntities(key, entityValues);
        });
    };

    // fetches labels and add them to the set
    const buildOptionsFromLabelsSearchQuery = (key: string) => {
      fetchQuery(labelsSearchQuery, {
        search: event.target.value !== 0 ? event.target.value : '',
        first: 10,
      })
        .toPromise()
        .then((data) => {
          const objectLabelEntities: EntityValue[] = (
            (data as LabelsQuerySearchQuery$data)?.labels?.edges ?? []
          ).flatMap(({ node }) => ((!node.value || !node.id) ? [] : {
            label: node.value,
            value: node.id,
            type: 'Label',
            color: node.color ?? undefined,
          }));
          unionSetEntities(key, [
            {
              label: t_i18n('No label'),
              value: null,
              type: 'Label',
              color: theme.palette.mode === 'dark' ? '#ffffff' : '#000000',
            },
            ...objectLabelEntities,
          ]);
        });
    };

    // fetches markings and add them to the set
    const buildOptionsFromMarkingsSearchQuery = (key: string) => {
      const allowedMarkingDefinitions = me.allowed_marking?.map(convertMarking) ?? [];
      const markedByEntities: EntityValue[] = allowedMarkingDefinitions.flatMap((m) => ({
        label: m.label,
        value: m.value,
        color: m.color,
        type: 'Marking-Definition',
      }));
      unionSetEntities(key, markedByEntities);
    };

    // fetches kill chain phases and add them to the set
    const buildOptionsFromKillChainPhasesSearchQuery = (key: string) => {
      fetchQuery(killChainPhasesSearchQuery, {
        search: event.target.value !== 0 ? event.target.value : '',
        first: 10,
      })
        .toPromise()
        .then((data) => {
          const killChainPhaseEntities = (
            (data as KillChainPhasesSearchQuery$data)?.killChainPhases?.edges ?? []
          ).map((n) => ({
            label: n
              ? `[${n.node.kill_chain_name}] ${n.node.phase_name}`
              : '',
            value: n?.node.id,
            type: 'Kill-Chain-Phase',
          }));
          unionSetEntities(key, killChainPhaseEntities);
        });
    };

    // fetches external references and add them to the set
    const buildOptionsFromExternalReferencesSearchQuery = (key: string) => {
      fetchQuery(externalReferencesQueriesSearchQuery, {
        search: event.target.value !== 0 ? event.target.value : '',
      })
        .toPromise()
        .then((data) => {
          const externalRefByEntities = (
            (data as ExternalReferencesQueriesSearchQuery$data)?.externalReferences?.edges ?? []
          ).map((n) => ({
            label: n?.node.external_id
              ? `${n?.node.source_name} (${n?.node.external_id})`
              : n?.node.source_name,
            value: n?.node.id,
            type: 'External-Reference',
          }));
          unionSetEntities(key, externalRefByEntities);
        });
    };

    // fetches stix meta objects by entity type and add them to the set
    const buildOptionsFromStixMetaObjectTypes = (key: string, metaTypes: string[]) => {
      if (metaTypes.includes('Label')) {
        buildOptionsFromLabelsSearchQuery(key);
      }
      if (metaTypes.includes('Marking-Definition')) {
        buildOptionsFromMarkingsSearchQuery(key);
      }
      if (metaTypes.includes('Kill-Chain-Phase')) {
        buildOptionsFromKillChainPhasesSearchQuery(key);
      }
      if (metaTypes.includes('External-Reference')) {
        buildOptionsFromExternalReferencesSearchQuery(key);
      }
    };

    // fetches stix core objects by entity type and add them to the set
    const buildOptionsFromStixCoreObjectTypes = (key: string, entityTypes: string[]) => {
      fetchQuery(filtersStixCoreObjectsSearchQuery, {
        types: (searchScope && searchScope[key]) || entityTypes,
        search: event.target.value !== 0 ? event.target.value : '',
        count: 100,
      })
        .toPromise()
        .then((data) => {
          const elementIdEntities: EntityValue[] = (
            (data as useSearchEntitiesStixCoreObjectsSearchQuery$data)?.stixCoreObjects?.edges ?? []
          ).map(({ node }) => ({
            label: getMainRepresentative(node),
            value: node.id,
            type: node.entity_type,
            parentTypes: node.parent_types.flatMap((t) => (t || [])),
          }));
          unionSetEntities(key, elementIdEntities);
        });
    };

    // fetches groups and add them to the set
    const buildOptionsFromGroupSearchQuery = (key: string) => {
      fetchQuery(groupsQuery, {
        search: event.target.value !== 0 ? event.target.value : '',
        first: 10,
      })
        .toPromise()
        .then((data) => {
          const groups: EntityValue[] = (
            (data as useSearchEntitiesGroupsQuery$data)?.groups
              ?.edges ?? []
          ).flatMap((n) => (!n ? [] : {
            label: n.node.name,
            value: n.node.id,
            type: n.node.entity_type,
          }));
          unionSetEntities(key, groups);
        });
    };

    // fetches groups and add them to the set
    const buildOptionsFromPirSearchQuery = (key: string) => {
      fetchQuery(pirsQuery, {
        search: event.target.value !== 0 ? event.target.value : '',
        first: 10,
      })
        .toPromise()
        .then((data) => {
          const pirs: EntityValue[] = (
            (data as useSearchEntitiesPirsQuery$data)?.pirs
              ?.edges ?? []
          ).flatMap((n) => (!n ? [] : {
            label: n.node.name,
            value: n.node.id,
            type: n.node.entity_type,
          }));
          unionSetEntities(key, pirs);
        });
    };

    // fetches identities by types and add them to the set
    const buildOptionsFromIdentitySearchQuery = (key: string, types: string[]) => {
      fetchQuery(identitySearchIdentitiesSearchQuery, {
        types,
        search: event.target.value !== 0 ? event.target.value : '',
        first: 10,
      })
        .toPromise()
        .then((data) => {
          const createdByEntities: EntityValue[] = (
            (data as IdentitySearchIdentitiesSearchQuery$data)?.identities
              ?.edges ?? []
          ).flatMap((n) => (!n ? [] : {
            label: n.node.name,
            value: n.node.id,
            type: n.node.entity_type,
          }));
          unionSetEntities(key, createdByEntities);
        });
    };

    // fetches members by types and add them to the set
    const buildOptionsFromMembersSearchQuery = (key: string, entityTypes: string[]) => {
      fetchQuery(objectAssigneeFieldMembersSearchQuery, {
        search: event.target.value !== 0 ? event.target.value : '',
        entityTypes,
        first: 10,
      })
        .toPromise()
        .then((data) => {
          const membersEntities = (
            (data as ObjectAssigneeFieldMembersSearchQuery$data)?.members
              ?.edges ?? []
          ).map((n) => ({
            label: n?.node.name,
            value: n?.node.id,
            type: n?.node.entity_type,
            group: n?.node.entity_type,
          }));
          unionSetEntities(key, membersEntities);
          if (entityTypes.includes('User')) { // add @me filter value
            unionSetEntities(key, [meEntity]);
          }
          const membersSystems = (
            (data as ObjectAssigneeFieldMembersSearchQuery$data)?.systemMembers
              ?.edges ?? []
          ).map((n) => ({
            label: n?.node.name,
            value: n?.node.id,
            type: n?.node.entity_type,
            group: n?.node.entity_type,
          }));
          unionSetEntities(key, membersSystems);
        });
    };

    // take the output of a request and add corresponding options in the set (+ cache the options)
    // it's used for creators, assignee and participants, their query responses are similar
    const buildCachedOptionsFromGenericFetchResponse = (
      key: string,
      type: string,
      data: IdentitySearchCreatorsSearchQuery$data['creators'], // this type is actually the same for the different queries we use, not only creators
    ) => {
      const newOptions: EntityValue[] = (data?.edges ?? []).map((n) => ({
        label: n?.node.name ?? '',
        value: n?.node.id ?? '',
        type,
      }));
      // always add myself to the possible creators (to be able to add a trigger even if I have not yet created any objects)
      if (!newOptions.find((usr) => usr.value === me.id)) {
        newOptions.push({
          label: me.name,
          value: me.id,
          type,
        });
      }
      // add @me value for filters with user id as values
      if (type === 'User') {
        newOptions.push(meEntity);
      }

      setCacheEntities({ ...cacheEntities, [key]: newOptions });
      unionSetEntities(filterKey, newOptions);
    };

    // static list building, no query to run
    // it can take an array of strings or EntityValues as input, for genericity
    // if groupedBy is set, the possible options will be duplicated for every group
    // if isLabelTranslated is set, string inputs will be translated to produce the option label
    const buildOptionsFromStaticList = (key: string, inputList: string[] | EntityValue[], groupedBy: string[] = [], isLabelTranslated = false) => {
      const ungroupedEntities: EntityValue[] = inputList.map((n) => (
        typeof n === 'string' ? {
          label: isLabelTranslated ? t_i18n(n) : n,
          value: n,
          type: 'Vocabulary',
        } : {
          label: n.label, // supposedly already translated, or do not require it
          value: n.value,
          type: 'Vocabulary',
          color: n.color ?? undefined,
        }));
      let entitiesToAdd = ungroupedEntities;
      if (groupedBy.length > 0) {
        entitiesToAdd = groupedBy
          .flatMap((group) => ungroupedEntities.map((item) => ({ ...item, group })));
      }
      unionSetEntities(key, entitiesToAdd);
    };

    const keysWithSpecificSearch = [
      'objectAssignee', // TODO add context info to indicate the usage is restricted
      'objectParticipant', // TODO restrict
      'creator_id', // TODO restrict
      'members_user', // for audit TODO register in audit (not for now)
      'members_group', // for audit TODO register in audit (not for now)
      'members_organization', // for audit TODO register in audit (not for now)
      'id', // regardingOf subfilter
      'connectedToId', // id of the listened entities in an instance trigger
      'sightedBy', // sighting relationship TODO remove because already in regardingOf, and migrate the key)
      'computed_reliability', // special key for the entity reliability, or the reliability of its author if no reliability is set
      'inPir',
    ].concat(entityTypesFilters)
      .concat(contextFilters);
    // case 1 : filter keys with specific behavior
    if (keysWithSpecificSearch.includes(filterKey)) {
      switch (filterKey) {
        case 'objectAssignee':
          if (!cacheEntities[filterKey]) {
            // fetch only the identities listed as assignee on at least 1 thing + myself
            fetchQuery(objectAssigneeFieldAssigneesSearchQuery, {
              entityTypes: searchContext.entityTypes ?? [],
            })
              .toPromise()
              .then((response) => {
                const data = response as ObjectAssigneeFieldAssigneesSearchQuery$data;
                buildCachedOptionsFromGenericFetchResponse(filterKey, 'User', data?.assignees);
              });
          }
          break;
        case 'objectParticipant':
          if (!cacheEntities[filterKey]) {
            // fetch only the identities listed as participants to at least 1 thing + myself
            fetchQuery(objectParticipantFieldParticipantsSearchQuery, {
              entityTypes: searchContext.entityTypes ?? [],
            })
              .toPromise()
              .then((response) => {
                const data = response as ObjectParticipantFieldParticipantsSearchQuery$data;
                buildCachedOptionsFromGenericFetchResponse(filterKey, 'User', data?.participants);
              });
          }
          break;
        // region member global
        case 'members_user':
          buildOptionsFromMembersSearchQuery(filterKey, ['User']);
          break;
        case 'members_group':
          buildOptionsFromMembersSearchQuery(filterKey, ['Group']);
          break;
        case 'inPir':
          buildOptionsFromPirSearchQuery(filterKey);
          break;
        case 'members_organization':
          buildOptionsFromMembersSearchQuery(filterKey, ['Organization']);
          break;
        // endregion
        // region user usage (with caching)
        case 'creator_id':
        case 'contextCreator':
          if (searchContext.connectorsScope && canDisplayAllUsers) {
            // fetch all the users
            fetchQuery(toolBarUsersLinesSearchQuery, {
              first: 10,
              orderBy: 'name',
              orderMode: 'asc',
            })
              .toPromise()
              .then((response) => {
                const data = response as DataTableToolBarUsersLinesSearchQuery$data;
                buildCachedOptionsFromGenericFetchResponse(filterKey, 'User', data?.users);
              });
          }
          if (!cacheEntities[filterKey]) {
            // fetch only the identities listed as creator of at least 1 thing + myself
            fetchQuery(identitySearchCreatorsSearchQuery, {
              entityTypes: searchContext.entityTypes ?? [],
            })
              .toPromise()
              .then((response) => {
                const data = response as IdentitySearchCreatorsSearchQuery$data;
                buildCachedOptionsFromGenericFetchResponse(filterKey, 'User', data?.creators);
              });
          }
          break;
        // endregion
        case 'contextCreatedBy':
          buildOptionsFromIdentitySearchQuery(filterKey, ['Organization', 'Individual', 'System']);
          break;
        case 'id':
        case 'connectedToId':
          buildOptionsFromStixCoreObjectTypes(filterKey, ['Stix-Core-Object']);
          break;
        case 'contextEntityId':
          buildOptionsFromStixCoreObjectTypes(filterKey, ['Stix-Core-Object']);
          buildOptionsFromMembersSearchQuery(filterKey, ['User', 'Group']);
          break;
        case 'sightedBy':
          fetchQuery(stixDomainObjectsLinesSearchQuery, {
            types: ['Sector', 'Organization', 'Individual', 'Region', 'Country', 'City'],
            search: event.target.value !== 0 ? event.target.value : '',
            count: 10,
          })
            .toPromise()
            .then((data) => {
              const sightedByEntities: EntityValue[] = (
                (data as StixDomainObjectsLinesSearchQuery$data)?.stixDomainObjects?.edges ?? []
              ).flatMap((n) => ((!n || !n.node) ? [] : {
                label: n.node.name ?? '',
                value: n.node.id,
                type: n.node.entity_type,
              }));
              unionSetEntities('sightedBy', sightedByEntities);
            });
          break;
        case 'computed_reliability':
          buildOptionsFromVocabularySearchQuery(filterKey, ['reliability_ov']);
          break;
        case 'contextObjectLabel':
          buildOptionsFromLabelsSearchQuery(filterKey);
          break;
        case 'contextObjectMarking':
          buildOptionsFromMarkingsSearchQuery(filterKey);
          break;
        // region entity and relation types
        case 'contextEntityType': {
          const elementTypeResult = [
            ...(schema.scos ?? []).map((n) => ({
              label: t_i18n(`entity_${n.label}`),
              value: n.label,
              type: n.label,
            })),
            ...(schema.sdos ?? []).map((n) => ({
              label: t_i18n(`entity_${n.label}`),
              value: n.label,
              type: n.label,
            })),
            ...['User', 'Group', 'Workspace', 'Label', 'Marking-Definition', 'Pir', 'DisseminationList', 'ExclusionList', 'DecayRule', 'EmailTemplate', 'CsvMapper', 'JsonMapper', 'StatusTemplate', 'TaxiiCollection', 'StreamCollection', 'Feed', 'Notifier', 'FintelDesign', 'RetentionRule'].map((n) => ({
              label: t_i18n(`entity_${n}`),
              value: n,
              type: n,
            })),
          ];
          const elementTypeTypes = elementTypeResult.sort((a, b) => a.label.localeCompare(b.label));
          unionSetEntities(filterKey, elementTypeTypes);
          break;
        }
        case 'elementWithTargetTypes':
        case 'entity_type':
        case 'entity_types':
        case 'type':
        case 'main_entity_type':
          if ( // case not abstract types
            availableEntityTypes
            && !availableEntityTypes.includes('Stix-Cyber-Observable')
            && !availableEntityTypes.includes('Stix-Domain-Object')
            && !availableEntityTypes.includes('Stix-Core-Object')
          ) {
            let completedAvailableEntityTypes = availableEntityTypes;
            if (availableEntityTypes.includes('Container')) {
              completedAvailableEntityTypes = completedAvailableEntityTypes
                .filter((type) => type !== 'Container')
                .concat(containerTypes);
            }
            if (availableEntityTypes.includes('Threat-Actor')) {
              completedAvailableEntityTypes = completedAvailableEntityTypes
                .filter((type) => type !== 'Threat-Actor')
                .concat(['Threat-Actor-Individual', 'Threat-Actor-Group']);
            }
            const entitiesTypes = completedAvailableEntityTypes
              .map((n) => ({
                label: t_i18n(displayEntityTypeForTranslation(n)),
                value: n,
                type: n,
              }))
              .sort((a, b) => a.label.localeCompare(b.label));
            unionSetEntities(filterKey, entitiesTypes);
          } else { // case abstract types
            let result: EntityValue[] = [];
            // push the observables
            if (
              !availableEntityTypes
              || availableEntityTypes.includes('Stix-Core-Object')
              || availableEntityTypes.includes('Stix-Cyber-Observable')
            ) {
              result = [
                ...(schema.scos ?? []).map((n) => ({
                  label: t_i18n(`entity_${n.label}`),
                  value: n.label,
                  type: n.label,
                })),
                ...result,
              ];
              // if there are not only stix cyber observables in the entity types list, add the 'Stix Cyber Observable' abstract type
              if (!availableEntityTypes
                || (availableEntityTypes && (availableEntityTypes.length > 1 || availableEntityTypes.includes('Stix-Core-Object')))) {
                result = [
                  {
                    label: t_i18n('entity_Stix-Cyber-Observable'),
                    value: 'Stix-Cyber-Observable',
                    type: 'Stix-Cyber-Observable',
                  },
                  ...result,
                ];
              }
            }
            // push the stix domain objects
            if (
              !availableEntityTypes
              || availableEntityTypes.includes('Stix-Core-Object')
              || availableEntityTypes.includes('Stix-Domain-Object')
            ) {
              result = [
                ...(schema.sdos ?? []).map((n) => ({
                  label: t_i18n(`entity_${n.label}`),
                  value: n.label,
                  type: n.label,
                })),
                ...result,
              ];
              // if there are not only stix domain objects in the entity types list, add the 'Stix Domain Object' abstract type
              if (!availableEntityTypes
                || (availableEntityTypes && (availableEntityTypes.length > 1 || availableEntityTypes.includes('Stix-Core-Object')))) {
                result = [
                  {
                    label: t_i18n('entity_Stix-Domain-Object'),
                    value: 'Stix-Domain-Object',
                    type: 'Stix-Domain-Object',
                  },
                  ...result,
                ];
              }
            }
            // push the stix core relationships types
            if (
              !availableEntityTypes
              || availableEntityTypes.includes('stix-core-relationship')
            ) {
              result = [
                ...(schema.scrs ?? []).map((n) => ({
                  label: t_i18n(`relationship_${n.label}`),
                  value: n.label,
                  type: n.label,
                })),
                ...result,
              ];
              // if there are not only stix core relationships in the entity types list, add the 'Stix Core Relationship' abstract type
              if (!availableEntityTypes
                || (availableEntityTypes && availableEntityTypes.length > 1)) {
                result = [
                  {
                    label: t_i18n('entity_Stix-Core-Relationship'),
                    value: 'Stix-Core-Relationship',
                    type: 'Stix-Core-Relationship',
                  },
                  ...result,
                ];
              }
            }
            // push the sighting relationship
            if (
              !availableEntityTypes
              || availableEntityTypes.includes('stix-sighting-relationship')
            ) {
              result = [
                ...result,
                {
                  label: t_i18n('relationship_stix-sighting-relationship'),
                  value: 'stix-sighting-relationship',
                  type: 'stix-sighting-relationship',
                },
              ];
            }
            // push the 'contains' relationship
            if (
              !availableEntityTypes
              || availableEntityTypes.includes('contains')
            ) {
              result = [
                ...result,
                {
                  label: t_i18n('relationship_object'),
                  value: 'object',
                  type: 'stix-internal-relationship',
                },
              ];
            }
            const entitiesTypes = result.sort((a, b) => a.label.localeCompare(b.label));
            unionSetEntities(filterKey, entitiesTypes);
          }
          break;
        case 'fromTypes':
        case 'toTypes':
          // for source type and target type, we need:
          // the observables
          // the stix domain objects
          // the stix core relationships
          unionSetEntities(
            filterKey,
            [
              ...(schema.scos ?? []).map((n) => ({
                label: t_i18n(`entity_${n.label}`),
                value: n.label,
                type: n.label,
              })),
              {
                label: t_i18n('entity_Stix-Cyber-Observable'),
                value: 'Stix-Cyber-Observable',
                type: 'Stix-Cyber-Observable',
              },
              ...(schema.sdos ?? []).map((n) => ({
                label: t_i18n(`entity_${n.label}`),
                value: n.label,
                type: n.label,
              })),
              {
                label: t_i18n('entity_Stix-Domain-Object'),
                value: 'Stix-Domain-Object',
                type: 'Stix-Domain-Object',
              },
              ...(schema.scrs ?? []).map((n) => ({
                label: t_i18n(`relationship_${n.label}`),
                value: n.label,
                type: n.label,
              })),
              {
                label: t_i18n('entity_Stix-Core-Relationship'),
                value: 'Stix-Core-Relationship',
                type: 'Stix-Core-Relationship',
              },
            ].sort((a, b) => a.label.localeCompare(b.label)),
          );
          break;
        case 'relationship_type': {
          let relationshipsTypes: { label: string, value: string, type: string }[] = [];
          if (availableRelationshipTypes && !isSubKey) { // if available RelationshipTypes is specified, we display only the specified relationship types
            relationshipsTypes = availableRelationshipTypes
              .map((n) => ({
                label: t_i18n(`relationship_${n.toString()}`),
                value: n,
                type: n,
              }));
          } else if (isSubKey || !searchContext.entityTypes) { // if relationship_type is the subKey of regarding_of, we always display all the relationship types
            relationshipsTypes = (schema.scrs ?? [])
              .map((n) => ({
                label: t_i18n(`relationship_${n.label}`),
                value: n.label,
                type: n.label,
              }))
              .concat([
                {
                  label: t_i18n('relationship_stix-sighting-relationship'),
                  value: 'stix-sighting-relationship',
                  type: 'stix-sighting-relationship',
                },
                {
                  label: t_i18n('relationship_object'),
                  value: 'object',
                  type: 'stix-internal-relationship',
                },
              ]);
          } else { // display relationship types according to searchContext.entityTypes
            const { entityTypes } = searchContext;
            if (entityTypes.includes('stix-core-relationship')) {
              relationshipsTypes = (schema.scrs ?? [])
                .map((n) => ({
                  label: t_i18n(`relationship_${n.label}`),
                  value: n.label,
                  type: n.label,
                }));
            }
            if (entityTypes.includes('stix-sighting-relationship')) {
              relationshipsTypes = [
                ...relationshipsTypes,
                {
                  label: t_i18n('relationship_stix-sighting-relationship'),
                  value: 'stix-sighting-relationship',
                  type: 'stix-sighting-relationship',
                },
              ];
            }
            if (entityTypes.includes('contains')) {
              relationshipsTypes = [
                ...relationshipsTypes,
                {
                  label: t_i18n('relationship_object'),
                  value: 'object',
                  type: 'stix-internal-relationship',
                },
              ];
            }
          }
          unionSetEntities(filterKey, relationshipsTypes.sort((a, b) => a.label.localeCompare(b.label)));
          break;
        }
        case 'x_opencti_main_observable_type':
        case 'exclusion_list_entity_types':
          fetchQuery(filtersSchemaSCOSearchQuery)
            .toPromise()
            .then((data) => {
              const mainObservableTypeEntities = (
                (data as useSearchEntitiesSchemaSCOSearchQuery$data)?.schemaSCOs
                  ?.edges ?? []
              ).map((n) => ({
                label: t_i18n(`entity_${n?.node.id}`),
                value: n?.node.id,
                type: n?.node.id,
              }));
              unionSetEntities(
                filterKey,
                mainObservableTypeEntities,
              );
            });
          break;
        // endregion
        default:
          break;
      }
    } else {
      // case 2: build according to the filter type
      // depending on the filter type, fetch the right data and build the options list
      const filterDefinition: FilterDefinition | undefined = getFilterDefinitionFromFilterKeysMap(filterKey, filterKeysMap);
      const filterType = filterDefinition?.type ?? 'undefined';
      switch (filterType) {
        case 'vocabulary':
          // eslint-disable-next-line no-case-declarations
          const vocabularyKey = filterDefinition?.elementsForFilterValuesSearch?.[0];
          if (vocabularyKey) buildOptionsFromVocabularySearchQuery(filterKey, [vocabularyKey]);
          break;
        case 'boolean':
          buildOptionsFromStaticList(filterKey, ['true', 'false'], [], true);
          break;
        case 'enum':
          // eslint-disable-next-line no-case-declarations
          const enumValues = filterDefinition?.elementsForFilterValuesSearch ?? [];
          buildOptionsFromStaticList(filterKey, enumValues, [], true);
          break;
        case 'id':
          // eslint-disable-next-line no-case-declarations
          const idEntityTypes = filterDefinition?.elementsForFilterValuesSearch ?? [];
          if (idEntityTypes) {
            const completedStixCoreObjectTypes = stixCoreObjectTypes.concat(['Stix-Core-Object', 'Stix-Cyber-Observable']);
            if (idEntityTypes.every((typeOfId) => completedStixCoreObjectTypes.includes(typeOfId))) { // Stix Core Objects
              buildOptionsFromStixCoreObjectTypes(filterKey, idEntityTypes);
            } else if (idEntityTypes.every((typeOfId) => schema.smos.map((n) => n.id).includes(typeOfId))) { // Stix Meta Objects
              buildOptionsFromStixMetaObjectTypes(filterKey, idEntityTypes);
            } else if (idEntityTypes.includes('Group')) {
              buildOptionsFromGroupSearchQuery(filterKey);
            } else if (idEntityTypes.includes('Notifier')) {
              fetchQuery(NotifierFieldQuery)
                .toPromise()
                .then((data) => {
                  const notifiers = (
                    (data as NotifierFieldSearchQuery$data).notificationNotifiers ?? []
                  ).map((n) => ({
                    label: n.name,
                    value: n.id,
                    type: 'Notifier',
                  }));
                  unionSetEntities(
                    filterKey,
                    notifiers,
                  );
                });
            } else if (idEntityTypes.includes('Trigger')) {
              fetchQuery(triggersQueriesSearchQuery, {
                search: event.target.value !== 0 ? event.target.value : '',
              })
                .toPromise()
                .then((data) => {
                  const triggers = (
                    (data as TriggersQueriesSearchQuery$data).triggers?.edges ?? []
                  ).map((n) => ({
                    label: n.node.name,
                    value: n.node.id,
                    type: 'Trigger',
                  }));
                  unionSetEntities(
                    filterKey,
                    triggers,
                  );
                });
            } else if (idEntityTypes.includes('StatusTemplate')) {
              fetchQuery(StatusTemplateFieldQuery, {
                first: 500,
              })
                .toPromise()
                .then((data) => {
                  const statusTemplateEntities: EntityValue[] = (
                    (data as StatusTemplateFieldSearchQuery$data)?.statusTemplates?.edges
                    ?? []
                  )
                    .flatMap((n) => (!n ? [] : {
                      label: n.node.name,
                      color: n.node.color,
                      value: n.node.id,
                      type: 'Vocabulary',
                    }))
                    .sort((a, b) => (a.label ?? '').localeCompare(b.label ?? ''));
                  unionSetEntities(filterKey, statusTemplateEntities);
                });
            } else if (idEntityTypes.includes('PublicDashboard')) {
              fetchQuery(workspacesQuery, {
                first: 500,
                filters: {
                  mode: 'and',
                  filters: [
                    { key: 'type', values: ['dashboard'] },
                  ],
                  filterGroups: [],
                },
              })
                .toPromise()
                .then((data: unknown) => {
                  const dashboards = ((data as useSearchEntitiesDashboardsQuery$data)?.workspaces?.edges ?? [])
                    .filter((n) => !R.isNil(n?.node))
                    .map((n) => ({
                      label: n?.node.name,
                      value: n?.node.id,
                      type: 'Dashboard',
                    }))
                    .sort((a, b) => (a.label ?? '').localeCompare(b.label ?? ''));
                  unionSetEntities(filterKey, dashboards);
                });
            }
          }
          break;
        default:
          break;
      }
    }
  };
  return [entities, searchEntities] as const;
};

export default useSearchEntities;
