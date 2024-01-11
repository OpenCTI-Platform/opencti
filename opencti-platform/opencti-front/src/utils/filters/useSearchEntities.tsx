import * as R from 'ramda';
import { Dispatch, useState } from 'react';
import { graphql } from 'react-relay';
import { SelectChangeEvent } from '@mui/material/Select';
import { markingDefinitionsLinesSearchQuery } from '@components/settings/marking_definitions/MarkingDefinitionsLines';
import { identitySearchCreatorsSearchQuery, identitySearchIdentitiesSearchQuery } from '@components/common/identities/IdentitySearch';
import { stixDomainObjectsLinesSearchQuery } from '@components/common/stix_domain_objects/StixDomainObjectsLines';
import { killChainPhasesLinesSearchQuery } from '@components/settings/kill_chain_phases/KillChainPhasesLines';
import { labelsSearchQuery } from '@components/settings/LabelsQuery';
import { attributesSearchQuery } from '@components/settings/AttributesQuery';
import { vocabularySearchQuery } from '@components/settings/VocabularyQuery';
import { objectAssigneeFieldAssigneesSearchQuery, objectAssigneeFieldMembersSearchQuery } from '@components/common/form/ObjectAssigneeField';
import { IdentitySearchIdentitiesSearchQuery$data } from '@components/common/identities/__generated__/IdentitySearchIdentitiesSearchQuery.graphql';
import { IdentitySearchCreatorsSearchQuery$data } from '@components/common/identities/__generated__/IdentitySearchCreatorsSearchQuery.graphql';
import { ObjectAssigneeFieldAssigneesSearchQuery$data } from '@components/common/form/__generated__/ObjectAssigneeFieldAssigneesSearchQuery.graphql';
import { StixDomainObjectsLinesSearchQuery$data } from '@components/common/stix_domain_objects/__generated__/StixDomainObjectsLinesSearchQuery.graphql';
import { MarkingDefinitionsLinesSearchQuery$data } from '@components/settings/marking_definitions/__generated__/MarkingDefinitionsLinesSearchQuery.graphql';
import { KillChainPhasesLinesSearchQuery$data } from '@components/settings/kill_chain_phases/__generated__/KillChainPhasesLinesSearchQuery.graphql';
import { LabelsQuerySearchQuery$data } from '@components/settings/__generated__/LabelsQuerySearchQuery.graphql';
import { AttributesQuerySearchQuery$data } from '@components/settings/__generated__/AttributesQuerySearchQuery.graphql';
import { VocabularyQuery$data } from '@components/settings/__generated__/VocabularyQuery.graphql';
import { ObjectAssigneeFieldMembersSearchQuery$data } from '@components/common/form/__generated__/ObjectAssigneeFieldMembersSearchQuery.graphql';
import { ObjectParticipantFieldParticipantsSearchQuery$data } from '@components/common/form/__generated__/ObjectParticipantFieldParticipantsSearchQuery.graphql';
import { objectParticipantFieldParticipantsSearchQuery } from '@components/common/form/ObjectParticipantField';
import { useTheme } from '@mui/styles';
import { StatusTemplateFieldQuery } from '@components/common/form/StatusTemplateField';
import { StatusTemplateFieldSearchQuery$data } from '@components/common/form/__generated__/StatusTemplateFieldSearchQuery.graphql';
import { buildScaleFilters } from '../hooks/useScale';
import useAuth from '../hooks/useAuth';
import { useSearchEntitiesStixCoreObjectsSearchQuery$data } from './__generated__/useSearchEntitiesStixCoreObjectsSearchQuery.graphql';
import { vocabCategoriesQuery } from '../hooks/useVocabularyCategory';
import { useFormatter } from '../../components/i18n';
import { defaultValue } from '../Graph';
import { fetchQuery } from '../../relay/environment';
import { useVocabularyCategoryQuery$data } from '../hooks/__generated__/useVocabularyCategoryQuery.graphql';
import { useSearchEntitiesStixCoreObjectsContainersSearchQuery$data } from './__generated__/useSearchEntitiesStixCoreObjectsContainersSearchQuery.graphql';
import { useSearchEntitiesSchemaSCOSearchQuery$data } from './__generated__/useSearchEntitiesSchemaSCOSearchQuery.graphql';
import type { Theme } from '../../components/Theme';

const filtersStixCoreObjectsContainersSearchQuery = graphql`
  query useSearchEntitiesStixCoreObjectsContainersSearchQuery(
    $search: String
    $filters: FilterGroup
  ) {
    containers(search: $search, filters: $filters) {
      edges {
        node {
          id
          entity_type
          parent_types
          representative {
            main
          }
        }
      }
    }
  }
`;

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
            edges {
              node {
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

export interface EntityValue {
  label?: string | null;
  value?: string | null;
  type?: string;
  group?: string;
  color?: string | null;
}

interface EntityWithLabelValue {
  label: string;
  value: string;
  type: string;
}

export interface SearchEntitiesProps {
  availableEntityTypes?: string[];
  availableRelationshipTypes?: string[];
  searchContext: { entityTypes: string[]; elementId?: string[] };
  searchScope: Record<string, string[]>;
  setInputValues: (value: { key: string, values: string[], operator?: string }[]) => void;
  allEntityTypes?: boolean;
}

const useSearchEntities = ({
  availableEntityTypes,
  availableRelationshipTypes,
  searchContext,
  searchScope,
  setInputValues,
  allEntityTypes,
}: {
  availableEntityTypes?: string[];
  availableRelationshipTypes?: string[];
  searchContext: { entityTypes: string[]; elementId?: string[] };
  searchScope: Record<string, string[]>;
  setInputValues: (
    value: { key: string; values: string[]; operator?: string }[],
  ) => void;
  allEntityTypes?: boolean;
}) => {
  const [entities, setEntities] = useState<Record<string, EntityValue[]>>({});
  const { t } = useFormatter();
  const { schema, me } = useAuth();
  const theme = useTheme() as Theme;

  const unionSetEntities = (key: string, newEntities: EntityValue[]) => setEntities((c) => ({
    ...c,
    [key]: [...newEntities, ...(c[key] ?? [])].filter(
      ({ value, group }, index, arr) => arr.findIndex((v) => v.value === value && v.group === group)
        === index,
    ),
  }));

  const entityType = searchContext?.entityTypes?.length > 0
    ? searchContext.entityTypes[0]
    : null;
  const confidences = buildScaleFilters(entityType, 'confidence');

  const searchEntities = (
    filterKey: string,
    cacheEntities: Record< string, { label: string; value: string; type: string }[] >,
    setCacheEntities: Dispatch< Record<string, { label: string; value: string; type: string }[]> >,
    event: SelectChangeEvent<string | number>,
  ) => {
    if (!event) {
      return;
    }

    const baseScores = ['1', '2', '3', '4', '5', '6', '7', '8', '9'];
    const scores = ['0', '10', '20', '30', '40', '50', '60', '70', '80', '90', '100'];
    const likelihoods = ['0', '15', '50', '75', '85'];

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

    // fetches runtime attributes by name and add them to the set
    // this query returns only the attributes used somewhere
    const buildOptionsFromAttributesSearchQuery = (attributeName: string) => {
      fetchQuery(attributesSearchQuery, {
        attributeName,
        search: event.target.value !== 0 ? event.target.value : '',
        first: 10,
      })
        .toPromise()
        .then((data) => {
          const sourceEntities = (
            (data as AttributesQuerySearchQuery$data)?.runtimeAttributes
              ?.edges ?? []
          ).map((n) => ({
            label: n?.node.value,
            value: n?.node.value,
            type: 'Vocabulary',
          }));
          unionSetEntities(attributeName, sourceEntities);
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
          const createdByEntities = (
            (data as IdentitySearchIdentitiesSearchQuery$data)?.identities
              ?.edges ?? []
          ).map((n) => ({
            label: n?.node.name,
            value: n?.node.id,
            type: n?.node.entity_type,
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
          }));
          unionSetEntities(key, membersEntities);
        });
    };

    // take the output of a request and add corresponding options in the set (+ cache the options)
    // it's used for creators, assignee and participants, their query responses are similar
    const buildCachedOptionsFromGenericFetchResponse = (
      key: string,
      type: string,
      data: IdentitySearchCreatorsSearchQuery$data['creators'], // this type is actually the same for the different queries we use, not only creators
    ) => {
      const newOptions = (data?.edges ?? []).map((n) => ({
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
          label: isLabelTranslated ? t(n) : n,
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
        entitiesToAdd = groupedBy.flatMap((group) => ungroupedEntities.map((item) => ({ ...item, group })));
      }
      unionSetEntities(key, entitiesToAdd);
    };

    // depending on filter key, fetch the right data and build the options list
    switch (filterKey) {
      // region member global
      case 'members_user':
        buildOptionsFromMembersSearchQuery(filterKey, ['User']);
        break;
      case 'members_group':
        buildOptionsFromMembersSearchQuery(filterKey, ['Group']);
        break;
      case 'members_organization':
        buildOptionsFromMembersSearchQuery(filterKey, ['Organization']);
        break;
      // endregion
      // region user usage (with caching)
      case 'creator_id':
      case 'contextCreator':
        if (!cacheEntities[filterKey]) {
          // fetch only the identities listed as creator of at least 1 thing + myself
          fetchQuery(identitySearchCreatorsSearchQuery, {
            entityTypes: searchContext?.entityTypes ?? [],
          })
            .toPromise()
            .then((response) => {
              const data = response as IdentitySearchCreatorsSearchQuery$data;
              buildCachedOptionsFromGenericFetchResponse(filterKey, 'Individual', data?.creators);
            });
        }
        break;
      case 'objectAssignee':
        if (!cacheEntities[filterKey]) {
          // fetch only the identities listed as assignee on at least 1 thing + myself
          fetchQuery(objectAssigneeFieldAssigneesSearchQuery, {
            entityTypes: searchContext?.entityTypes ?? [],
          })
            .toPromise()
            .then((response) => {
              const data = response as ObjectAssigneeFieldAssigneesSearchQuery$data;
              buildCachedOptionsFromGenericFetchResponse(filterKey, 'Individual', data?.assignees);
            });
        }
        break;
      case 'objectParticipant':
        if (!cacheEntities[filterKey]) {
          // fetch only the identities listed as participants to at least 1 thing + myself
          fetchQuery(objectParticipantFieldParticipantsSearchQuery, {
            entityTypes: searchContext?.entityTypes ?? [],
          })
            .toPromise()
            .then((response) => {
              const data = response as ObjectParticipantFieldParticipantsSearchQuery$data;
              buildCachedOptionsFromGenericFetchResponse(filterKey, 'User', data?.participants);
            });
        }
        break;
        // endregion
      case 'createdBy':
      case 'contextCreatedBy':
        buildOptionsFromIdentitySearchQuery(filterKey, ['Organization', 'Individual', 'System']);
        break;
      case 'toSightingId':
        buildOptionsFromIdentitySearchQuery(filterKey, ['Identity']);
        break;
      case 'sightedBy':
        fetchQuery(stixDomainObjectsLinesSearchQuery, {
          types: ['Sector', 'Organization', 'Individual', 'Region', 'Country', 'City'],
          search: event.target.value !== 0 ? event.target.value : '',
          count: 10,
        })
          .toPromise()
          .then((data) => {
            const sightedByEntities = (
              (data as StixDomainObjectsLinesSearchQuery$data)?.stixDomainObjects?.edges ?? []
            ).map((n) => ({
              label: n?.node.name,
              value: n?.node.id,
              type: n?.node.entity_type,
            }));
            unionSetEntities('sightedBy', sightedByEntities);
          });
        break;
      case 'id':
      case 'elementId':
      case 'contextEntityId':
      case 'connectedToId':
      case 'fromId':
      case 'toId':
      case 'targets':
      case 'objects':
      case 'indicates':
        fetchQuery(filtersStixCoreObjectsSearchQuery, {
          types: (searchScope && searchScope[filterKey]) || ['Stix-Core-Object'],
          search: event.target.value !== 0 ? event.target.value : '',
          count: 100,
        })
          .toPromise()
          .then((data) => {
            const elementIdEntities = (
              (data as useSearchEntitiesStixCoreObjectsSearchQuery$data)?.stixCoreObjects?.edges ?? []
            ).map((n) => ({
              label: defaultValue(n?.node),
              value: n?.node.id,
              type: n?.node.entity_type,
              parentTypes: n?.node.parent_types,
            }));
            unionSetEntities(filterKey, elementIdEntities);
          });
        break;
      case 'containers': {
        const filters = [];
        if (searchContext?.elementId) filters.push({ key: 'objects', values: [searchContext?.elementId] });
        if (availableEntityTypes) filters.push({ key: 'entity_type', values: availableEntityTypes });
        fetchQuery(filtersStixCoreObjectsContainersSearchQuery, {
          search: event.target.value !== 0 ? event.target.value : '',
          count: 50,
          filters: {
            mode: 'and',
            filters,
            filterGroups: [],
          },
        })
          .toPromise()
          .then((data) => {
            const containerEntities = (
              (data as useSearchEntitiesStixCoreObjectsContainersSearchQuery$data)?.containers?.edges ?? []
            ).map((n) => ({
              label: n?.node.representative.main,
              value: n?.node.id,
              type: n?.node.entity_type,
              parentTypes: n?.node.parent_types,
            }));
            unionSetEntities(filterKey, containerEntities);
          });
        break;
      }
      case 'objectMarking':
      case 'contextObjectMarking':
        fetchQuery(markingDefinitionsLinesSearchQuery, {
          search: event.target.value !== 0 ? event.target.value : '',
        })
          .toPromise()
          .then((data) => {
            const markedByEntities = (
              (data as MarkingDefinitionsLinesSearchQuery$data)?.markingDefinitions?.edges ?? []
            ).map((n) => ({
              label: n?.node.definition,
              value: n?.node.id,
              type: 'Marking-Definition',
              color: n?.node.x_opencti_color,
            }));
            unionSetEntities(filterKey, markedByEntities);
          });
        break;
      case 'killChainPhases':
        fetchQuery(killChainPhasesLinesSearchQuery, {
          search: event.target.value !== 0 ? event.target.value : '',
          first: 10,
        })
          .toPromise()
          .then((data) => {
            const killChainPhaseEntities = (
              (data as KillChainPhasesLinesSearchQuery$data)?.killChainPhases?.edges ?? []
            ).map((n) => ({
              label: n
                ? `[${n.node.kill_chain_name}] ${n.node.phase_name}`
                : '',
              value: n?.node.id,
              type: 'Kill-Chain-Phase',
            }));
            unionSetEntities(filterKey, killChainPhaseEntities);
          });
        break;
      case 'objectLabel':
      case 'contextObjectLabel':
        fetchQuery(labelsSearchQuery, {
          search: event.target.value !== 0 ? event.target.value : '',
          first: 10,
        })
          .toPromise()
          .then((data) => {
            const objectLabelEntities = (
              (data as LabelsQuerySearchQuery$data)?.labels?.edges ?? []
            ).map((n) => ({
              label: n?.node.value,
              value: n?.node.id,
              type: 'Label',
              color: n?.node.color,
            }));
            unionSetEntities(filterKey, [
              {
                label: t('No label'),
                value: null,
                type: 'Label',
                color: theme.palette.mode === 'dark' ? '#ffffff' : '#000000',
              },
              ...objectLabelEntities,
            ]);
          });
        break;
      case 'x_opencti_base_score': {
        buildOptionsFromStaticList(filterKey, baseScores, ['lte', 'gt']);
        break;
      }
      // region confidence
      case 'confidence': {
        buildOptionsFromStaticList(filterKey, confidences, ['lte', 'gt']);
        break;
      }
      case 'confidence_gt': {
        buildOptionsFromStaticList(filterKey, confidences);
        break;
      }
      case 'confidence_lte': {
        buildOptionsFromStaticList(filterKey, confidences);
        break;
      }
      // endregion
      // region likelihood
      case 'likelihood': {
        buildOptionsFromStaticList(filterKey, likelihoods, ['lte', 'gt']);
        break;
      }
      case 'likelihood_gt': {
        buildOptionsFromStaticList(filterKey, likelihoods);
        break;
      }
      case 'likelihood_lte': {
        buildOptionsFromStaticList(filterKey, likelihoods);
        break;
      }
      // endregion
      // region x_opencti_score
      case 'x_opencti_score': {
        buildOptionsFromStaticList(filterKey, scores, ['lte', 'gt']);
        break;
      }
      case 'x_opencti_score_gt': {
        buildOptionsFromStaticList(filterKey, scores);
        break;
      }
      case 'x_opencti_score_lte': {
        buildOptionsFromStaticList(filterKey, scores);
        break;
      }
      // endregion
      case 'x_opencti_detection': {
        buildOptionsFromStaticList(filterKey, ['true', 'false'], [], true);
        break;
      }
      case 'based-on': {
        fetchQuery(filtersStixCoreObjectsSearchQuery, {
          types: (searchScope && searchScope[filterKey]) || [
            'Stix-Cyber-Observable',
          ],
          search: event.target.value !== 0 ? event.target.value : '',
          count: 100,
        })
          .toPromise()
          .then((data) => {
            const elementIdEntities = (
              (data as useSearchEntitiesStixCoreObjectsSearchQuery$data)
                ?.stixCoreObjects?.edges ?? []
            ).map((n) => ({
              label: defaultValue(n?.node),
              value: n?.node.id,
              type: n?.node.entity_type,
              parentTypes: n?.node.parent_types,
            }));
            unionSetEntities(filterKey, elementIdEntities);
          });
        break;
      }
      case 'revoked': {
        buildOptionsFromStaticList(filterKey, ['true', 'false'], [], true);
        break;
      }
      case 'trigger_type': {
        buildOptionsFromStaticList(filterKey, ['digest', 'live'], [], true);
        break;
      }
      case 'instance_trigger': {
        buildOptionsFromStaticList(filterKey, ['true', 'false'], [], true);
        break;
      }
      case 'is_read': {
        buildOptionsFromStaticList(filterKey, ['true', 'false'], [], true);
        break;
      }
      case 'event_type': {
        buildOptionsFromStaticList(filterKey, ['authentication', 'read', 'mutation', 'file', 'command']);
        break;
      }
      case 'event_scope': {
        buildOptionsFromStaticList(
          filterKey,
          ['create', 'update', 'delete', 'read', 'search', 'enrich', 'download', 'import', 'export', 'login', 'logout'],
        );
        break;
      }
      case 'priority':
        buildOptionsFromVocabularySearchQuery(filterKey, ['case_priority_ov']);
        break;
      case 'severity':
        buildOptionsFromVocabularySearchQuery(filterKey, ['case_severity_ov', 'incident_severity_ov']);
        break;
      case 'pattern_type':
        buildOptionsFromVocabularySearchQuery(filterKey, ['pattern_type_ov']);
        break;
      case 'malware_types':
        buildOptionsFromVocabularySearchQuery(filterKey, ['malware_type_ov']);
        break;
      case 'x_opencti_reliability':
      case 'source_reliability':
        buildOptionsFromVocabularySearchQuery(filterKey, ['reliability_ov']);
        break;
      case 'indicator_types':
        buildOptionsFromVocabularySearchQuery(filterKey, ['indicator_type_ov']);
        break;
      case 'incident_type':
        buildOptionsFromVocabularySearchQuery(filterKey, ['incident_type_ov']);
        break;
      case 'report_types':
        buildOptionsFromVocabularySearchQuery(filterKey, ['report_types_ov']);
        break;
      case 'channel_types':
        buildOptionsFromVocabularySearchQuery(filterKey, ['channel_types_ov']);
        break;
      case 'event_types':
        buildOptionsFromVocabularySearchQuery(filterKey, ['event_type_ov']);
        break;
      case 'context':
        buildOptionsFromVocabularySearchQuery(filterKey, ['grouping_context_ov']);
        break;

      case 'x_opencti_base_severity':
      case 'x_opencti_attack_vector':
      case 'x_opencti_organization_type':
      case 'source':
        buildOptionsFromAttributesSearchQuery(filterKey);
        break;
      case 'workflow_id':
        fetchQuery(StatusTemplateFieldQuery, {
          first: 500,
        })
          .toPromise()
          .then((data) => {
            const statusTemplateEntities = (
              (data as StatusTemplateFieldSearchQuery$data)?.statusTemplates?.edges
              ?? []
            )
              .filter((n) => !R.isNil(n?.node))
              .map((n) => ({
                label: n?.node.name,
                color: n?.node.color,
                value: n?.node.id,
                type: 'Vocabulary',
              }))
              .sort((a, b) => (a.label ?? '').localeCompare(b.label ?? ''));
            unionSetEntities('workflow_id', statusTemplateEntities);
          });
        break;
      case 'x_opencti_main_observable_type':
        fetchQuery(filtersSchemaSCOSearchQuery)
          .toPromise()
          .then((data) => {
            const mainObservableTypeEntities = (
              (data as useSearchEntitiesSchemaSCOSearchQuery$data)?.schemaSCOs
                ?.edges ?? []
            ).map((n) => ({
              label: n?.node.label,
              value: n?.node.id,
              type: 'Vocabulary',
            }));
            unionSetEntities(
              filterKey,
              mainObservableTypeEntities,
            );
          });
        break;
      // region entity and relation types
      // The options for these filter keys are built thanks to the schema
      case 'contextEntityType': {
        let elementTypeResult = [] as EntityWithLabelValue[];
        elementTypeResult = [
          ...(schema.scos ?? []).map((n) => ({
            label: t(`entity_${n.label}`),
            value: n.label,
            type: n.label,
          })),
          ...elementTypeResult,
        ];
        elementTypeResult = [
          ...(schema.sdos ?? []).map((n) => ({
            label: t(`entity_${n.label}`),
            value: n.label,
            type: n.label,
          })),
          ...elementTypeResult,
        ];
        const elementTypeTypes = elementTypeResult.sort((a, b) => a.label.localeCompare(b.label));
        unionSetEntities(filterKey, elementTypeTypes);
        break;
      }
      case 'elementWithTargetTypes':
      case 'entity_type':
      case 'entity_types':
      case 'fromTypes':
      case 'toTypes':
        if (
          availableEntityTypes
          && !availableEntityTypes.includes('Stix-Cyber-Observable')
          && !availableEntityTypes.includes('Stix-Domain-Object')
          && !availableEntityTypes.includes('Stix-Core-Object')
        ) {
          const entitiesTypes = availableEntityTypes
            .map((n) => ({
              label: t(
                n.toString()[0] === n.toString()[0].toUpperCase()
                  ? `entity_${n.toString()}`
                  : `relationship_${n.toString()}`,
              ),
              value: n,
              type: n,
            }))
            .sort((a, b) => a.label.localeCompare(b.label));
          if (allEntityTypes) {
            entitiesTypes.unshift({
              label: t('entity_All'),
              value: 'all',
              type: 'entity',
            });
          }
          unionSetEntities(filterKey, entitiesTypes);
        } else {
          let result = [] as EntityWithLabelValue[];
          if (
            !availableEntityTypes
            || availableEntityTypes.includes('Stix-Core-Object')
            || availableEntityTypes.includes('Stix-Cyber-Observable')
          ) {
            result = [
              ...(schema.scos ?? []).map((n) => ({
                label: t(`entity_${n.label}`),
                value: n.label,
                type: n.label,
              })),
              ...result,
              {
                label: t('entity_Stix-Cyber-Observable'),
                value: 'Stix-Cyber-Observable',
                type: 'Stix-Cyber-Observable',
              },
            ];
          }
          if (
            !availableEntityTypes
            || availableEntityTypes.includes('Stix-Core-Object')
            || availableEntityTypes.includes('Stix-Domain-Object')
          ) {
            result = [
              ...(schema.sdos ?? []).map((n) => ({
                label: t(`entity_${n.label}`),
                value: n.label,
                type: n.label,
              })),
              {
                label: t('entity_Stix-Domain-Object'),
                value: 'Stix-Domain-Object',
                type: 'Stix-Domain-Object',
              },
              ...result,
            ];
          }
          if (
            !availableEntityTypes
            || availableEntityTypes.includes('stix-core-relationship')
          ) {
            result = [
              ...(schema.scrs ?? []).map((n) => ({
                label: t(`relationship_${n.label}`),
                value: n.label,
                type: n.label,
              })),
              ...result,
              {
                label: t('relationship_stix-sighting-relationship'),
                value: 'stix-sighting-relationship',
                type: 'stix-sighting-relationship',
              },
            ];
          }
          const entitiesTypes = result.sort((a, b) => a.label.localeCompare(b.label));
          if (allEntityTypes) {
            entitiesTypes.unshift({
              label: t('entity_All'),
              value: 'all',
              type: 'entity',
            });
          }
          unionSetEntities(filterKey, entitiesTypes);
        }
        break;
      case 'relationship_type': {
        if (availableRelationshipTypes) {
          const relationshipsTypes = availableRelationshipTypes
            .map((n) => ({
              label: t(`relationship_${n.toString()}`),
              value: n,
              type: n,
            }))
            .sort((a, b) => a.label.localeCompare(b.label));
          unionSetEntities(filterKey, relationshipsTypes);
        } else {
          const relationshipsTypes = (schema.scrs ?? [])
            .map((n) => ({
              label: t(`relationship_${n.label}`),
              value: n.label,
              type: n.label,
            }))
            .concat([
              {
                label: t('relationship_stix-sighting-relationship'),
                value: 'stix-sighting-relationship',
                type: 'stix-sighting-relationship',
              },
              {
                label: t('relationship_object'),
                value: 'object',
                type: 'stix-internal-relationship',
              },
            ])
            .sort((a, b) => a.label.localeCompare(b.label));
          unionSetEntities(filterKey, relationshipsTypes);
        }
        break;
      }
      // endregion
      case 'category':
        fetchQuery(vocabCategoriesQuery)
          .toPromise()
          .then((data) => {
            unionSetEntities(
              filterKey,
              (
                data as useVocabularyCategoryQuery$data
              ).vocabularyCategories.map(({ key }) => ({
                label: key,
                value: key,
                type: 'Vocabulary',
              })),
            );
          });
        break;
      case 'container_type': {
        const containersTypes = [
          'Note',
          'Observed-Data',
          'Opinion',
          'Report',
          'Grouping',
          'Case',
        ]
          .map((n) => ({
            label: t(
              n.toString()[0] === n.toString()[0].toUpperCase()
                ? `entity_${n.toString()}`
                : `relationship_${n.toString()}`,
            ),
            value: n,
            type: n,
          }))
          .sort((a, b) => a.label.localeCompare(b.label));
        unionSetEntities(filterKey, containersTypes);
        break;
      }
      case 'x_opencti_negative': {
        const negativeValue = [true, false].map((n) => ({
          label: t(n ? 'False positive' : 'True positive'),
          value: n.toString(),
          type: 'Vocabulary',
        }));
        unionSetEntities(filterKey, negativeValue);
        break;
      }
      case 'note_types':
        buildOptionsFromVocabularySearchQuery(filterKey, ['note_types_ov']);
        break;
      default:
        break;
    }
  };
  return [entities, searchEntities];
};

export default useSearchEntities;
