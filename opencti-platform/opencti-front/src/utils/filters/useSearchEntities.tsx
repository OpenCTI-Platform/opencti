import * as R from 'ramda';
import { useTheme } from '@mui/styles';
import { Dispatch, useState } from 'react';
import { graphql } from 'react-relay';
import { SelectChangeEvent } from '@mui/material/Select';
import { fetchQuery } from '../../relay/environment';
import {
  identitySearchCreatorsSearchQuery,
  identitySearchIdentitiesSearchQuery,
} from '../../private/components/common/identities/IdentitySearch';
import { stixDomainObjectsLinesSearchQuery } from '../../private/components/common/stix_domain_objects/StixDomainObjectsLines';
import { defaultValue } from '../Graph';
import { markingDefinitionsLinesSearchQuery } from '../../private/components/settings/marking_definitions/MarkingDefinitionsLines';
import { killChainPhasesLinesSearchQuery } from '../../private/components/settings/kill_chain_phases/KillChainPhasesLines';
import { labelsSearchQuery } from '../../private/components/settings/LabelsQuery';
import { attributesSearchQuery } from '../../private/components/settings/AttributesQuery';
import { statusFieldStatusesSearchQuery } from '../../private/components/common/form/StatusField';
import { useFormatter } from '../../components/i18n';
import { vocabCategoriesQuery } from '../hooks/useVocabularyCategory';
import { vocabularySearchQuery } from '../../private/components/settings/VocabularyQuery';
import {
  objectAssigneeFieldAssigneesSearchQuery,
  objectAssigneeFieldMembersSearchQuery,
} from '../../private/components/common/form/ObjectAssigneeField';
import { IdentitySearchIdentitiesSearchQuery$data } from '../../private/components/common/identities/__generated__/IdentitySearchIdentitiesSearchQuery.graphql';
import { IdentitySearchCreatorsSearchQuery$data } from '../../private/components/common/identities/__generated__/IdentitySearchCreatorsSearchQuery.graphql';
import { ObjectAssigneeFieldAssigneesSearchQuery$data } from '../../private/components/common/form/__generated__/ObjectAssigneeFieldAssigneesSearchQuery.graphql';
import { StixDomainObjectsLinesSearchQuery$data } from '../../private/components/common/stix_domain_objects/__generated__/StixDomainObjectsLinesSearchQuery.graphql';
import { useSearchEntitiesStixCoreObjectsSearchQuery$data } from './__generated__/useSearchEntitiesStixCoreObjectsSearchQuery.graphql';
import { MarkingDefinitionsLinesSearchQuery$data } from '../../private/components/settings/marking_definitions/__generated__/MarkingDefinitionsLinesSearchQuery.graphql';
import { KillChainPhasesLinesSearchQuery$data } from '../../private/components/settings/kill_chain_phases/__generated__/KillChainPhasesLinesSearchQuery.graphql';
import { LabelsQuerySearchQuery$data } from '../../private/components/settings/__generated__/LabelsQuerySearchQuery.graphql';
import { AttributesQuerySearchQuery$data } from '../../private/components/settings/__generated__/AttributesQuerySearchQuery.graphql';
import { StatusFieldStatusesSearchQuery$data } from '../../private/components/common/form/__generated__/StatusFieldStatusesSearchQuery.graphql';
import { VocabularyQuery$data } from '../../private/components/settings/__generated__/VocabularyQuery.graphql';
import { useVocabularyCategoryQuery$data } from '../hooks/__generated__/useVocabularyCategoryQuery.graphql';
import { Theme } from '../../components/Theme';
import useAuth from '../hooks/useAuth';
import { ObjectAssigneeFieldMembersSearchQuery$data } from '../../private/components/common/form/__generated__/ObjectAssigneeFieldMembersSearchQuery.graphql';

const filtersStixCoreObjectsSearchQuery = graphql`
  query useSearchEntitiesStixCoreObjectsSearchQuery(
    $search: String
    $types: [String]
    $count: Int
    $filters: [StixCoreObjectsFiltering]
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
          ... on ThreatActorGroup {
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

const useSearchEntities = ({
  availableEntityTypes,
  availableRelationshipTypes,
  searchScope,
  setInputValues,
  allEntityTypes,
}: {
  availableEntityTypes?: string[];
  availableRelationshipTypes?: string[];
  searchScope: Record<string, string[]>;
  setInputValues: Dispatch<Record<string, string | Date>>;
  allEntityTypes?: boolean;
}) => {
  const [entities, setEntities] = useState<Record<string, EntityValue[]>>({});
  const { t } = useFormatter();
  const { schema } = useAuth();
  const theme = useTheme() as Theme;
  const unionSetEntities = (key: string, newEntities: EntityValue[]) => setEntities((c) => ({
    ...c,
    [key]: [...newEntities, ...(c[key] ?? [])].filter(
      ({ value, group }, index, arr) => arr.findIndex((v) => v.value === value && v.group === group) === index,
    ),
  }));
  const searchEntities = (
    filterKey: string,
    searchContext: { entityTypes: string[] },
    cacheEntities: Record<
    string,
    { label: string; value: string; type: string }[]
    >,
    setCacheEntities: Dispatch<
    Record<string, { label: string; value: string; type: string }[]>
    >,
    event: SelectChangeEvent<string | number>,
  ) => {
    const baseScores = ['1', '2', '3', '4', '5', '6', '7', '8', '9'];
    const scores = [
      '0',
      '10',
      '20',
      '30',
      '40',
      '50',
      '60',
      '70',
      '80',
      '90',
      '100',
    ];
    const confidences = ['0', '15', '50', '75', '85'];
    const likelihoods = ['0', '15', '50', '75', '85'];
    if (!event) {
      return;
    }
    setInputValues(((c: Record<string, string | Date>) => ({
      ...c,
      [filterKey]: event.target.value,
    })) as unknown as Record<string, string | Date>);
    switch (filterKey) {
      case 'toSightingId':
        fetchQuery(identitySearchIdentitiesSearchQuery, {
          types: ['Identity'],
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
            unionSetEntities('toSightingId', createdByEntities);
          });
        break;
      // region member global
      case 'members_user': // All groups, only for granted users
        fetchQuery(objectAssigneeFieldMembersSearchQuery, {
          search: event.target.value !== 0 ? event.target.value : '',
          entityTypes: ['User'],
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
            unionSetEntities('members_user', membersEntities);
          });
        break;
      case 'members_group': // All groups, only for granted users
        fetchQuery(objectAssigneeFieldMembersSearchQuery, {
          search: event.target.value !== 0 ? event.target.value : '',
          entityTypes: ['Group'],
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
            unionSetEntities('members_group', membersEntities);
          });
        break;
      case 'members_organization': // All groups, only for granted users
        fetchQuery(objectAssigneeFieldMembersSearchQuery, {
          search: event.target.value !== 0 ? event.target.value : '',
          entityTypes: ['Organization'],
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
            unionSetEntities('members_organization', membersEntities);
          });
        break;
      // endregion
      // region user usage
      case 'creator': // only used
        if (!cacheEntities[filterKey]) {
          fetchQuery(identitySearchCreatorsSearchQuery, {
            entityTypes: searchContext?.entityTypes ?? [],
          })
            .toPromise()
            .then((data) => {
              const creators = (
                (data as IdentitySearchCreatorsSearchQuery$data)?.creators
                  ?.edges ?? []
              ).map((n) => ({
                label: n?.node.name ?? '',
                value: n?.node.id ?? '',
                type: 'Individual',
              }));
              setCacheEntities({ ...cacheEntities, [filterKey]: creators });
              unionSetEntities('creator', creators);
            });
        }
        break;
      case 'assigneeTo': // only used
        if (!cacheEntities[filterKey]) {
          fetchQuery(objectAssigneeFieldAssigneesSearchQuery, {
            entityTypes: searchContext?.entityTypes ?? [],
          })
            .toPromise()
            .then((data) => {
              const assigneeToEntities = (
                (data as ObjectAssigneeFieldAssigneesSearchQuery$data)
                  ?.assignees?.edges ?? []
              ).map((n) => ({
                label: n?.node.name ?? '',
                value: n?.node.id ?? '',
                type: 'User',
              }));
              setCacheEntities({
                ...cacheEntities,
                [filterKey]: assigneeToEntities,
              });
              unionSetEntities('assigneeTo', assigneeToEntities);
            });
        }
        break;
      // endregion
      case 'createdBy':
        fetchQuery(identitySearchIdentitiesSearchQuery, {
          types: ['Organization', 'Individual', 'System'],
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
            unionSetEntities('createdBy', createdByEntities);
          });
        break;
      case 'sightedBy':
        fetchQuery(stixDomainObjectsLinesSearchQuery, {
          types: [
            'Sector',
            'Organization',
            'Individual',
            'Region',
            'Country',
            'City',
          ],
          search: event.target.value !== 0 ? event.target.value : '',
          count: 10,
        })
          .toPromise()
          .then((data) => {
            const sightedByEntities = (
              (data as StixDomainObjectsLinesSearchQuery$data)
                ?.stixDomainObjects?.edges ?? []
            ).map((n) => ({
              label: n?.node.name,
              value: n?.node.id,
              type: n?.node.entity_type,
            }));
            unionSetEntities('sightedBy', sightedByEntities);
          });
        break;
      case 'elementId':
        fetchQuery(filtersStixCoreObjectsSearchQuery, {
          types: (searchScope && searchScope.elementId) || ['Stix-Core-Object'],
          search: event.target.value !== 0 ? event.target.value : '',
          count: 50,
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
            unionSetEntities('elementId', elementIdEntities);
          });
        break;
      case 'fromId':
        fetchQuery(filtersStixCoreObjectsSearchQuery, {
          types: (searchScope && searchScope.fromId) || ['Stix-Core-Object'],
          search: event.target.value !== 0 ? event.target.value : '',
          count: 50,
        })
          .toPromise()
          .then((data) => {
            const fromIdEntities = (
              (data as useSearchEntitiesStixCoreObjectsSearchQuery$data)
                ?.stixCoreObjects?.edges ?? []
            ).map((n) => ({
              label: defaultValue(n?.node),
              value: n?.node.id,
              type: n?.node.entity_type,
              parentTypes: n?.node.parent_types,
            }));
            unionSetEntities('fromId', fromIdEntities);
          });
        break;
      case 'toId':
        fetchQuery(filtersStixCoreObjectsSearchQuery, {
          types: (searchScope && searchScope.toId) || ['Stix-Core-Object'],
          search: event.target.value !== 0 ? event.target.value : '',
          count: 100,
        })
          .toPromise()
          .then((data) => {
            const toIdEntities = (
              (data as useSearchEntitiesStixCoreObjectsSearchQuery$data)
                ?.stixCoreObjects?.edges ?? []
            ).map((n) => ({
              label: defaultValue(n?.node),
              value: n?.node.id,
              type: n?.node.entity_type,
              parentTypes: n?.node.parent_types,
            }));
            unionSetEntities('toId', toIdEntities);
          });
        break;
      case 'targets':
        fetchQuery(filtersStixCoreObjectsSearchQuery, {
          types: (searchScope && searchScope.targets) || ['Stix-Core-Object'],
          search: event.target.value !== 0 ? event.target.value : '',
          count: 100,
        })
          .toPromise()
          .then((data) => {
            const toIdEntities = (
              (data as useSearchEntitiesStixCoreObjectsSearchQuery$data)
                ?.stixCoreObjects?.edges ?? []
            ).map((n) => ({
              label: defaultValue(n?.node),
              value: n?.node.id,
              type: n?.node.entity_type,
              parentTypes: n?.node.parent_types,
            }));
            unionSetEntities('targets', toIdEntities);
          });
        break;
      case 'objectContains':
        fetchQuery(filtersStixCoreObjectsSearchQuery, {
          types: (searchScope && searchScope.objectContains) || [
            'Stix-Core-Object',
          ],
          search: event.target.value !== 0 ? event.target.value : '',
          count: 50,
        })
          .toPromise()
          .then((data) => {
            const objectContainsEntities = (
              (data as useSearchEntitiesStixCoreObjectsSearchQuery$data)
                ?.stixCoreObjects?.edges ?? []
            ).map((n) => ({
              label: defaultValue(n?.node),
              value: n?.node.id,
              type: n?.node.entity_type,
              parentTypes: n?.node.parent_types,
            }));
            unionSetEntities('objectContains', objectContainsEntities);
          });
        break;
      case 'indicates':
        fetchQuery(filtersStixCoreObjectsSearchQuery, {
          types: (searchScope && searchScope.indicates) || ['Stix-Core-Object'],
          search: event.target.value !== 0 ? event.target.value : '',
          count: 50,
        })
          .toPromise()
          .then((data) => {
            const indicatesEntities = (
              (data as useSearchEntitiesStixCoreObjectsSearchQuery$data)
                ?.stixCoreObjects?.edges ?? []
            ).map((n) => ({
              label: defaultValue(n?.node),
              value: n?.node.id,
              type: n?.node.entity_type,
              parentTypes: n?.node.parent_types,
            }));
            unionSetEntities('indicates', indicatesEntities);
          });
        break;
      case 'markedBy':
        fetchQuery(markingDefinitionsLinesSearchQuery, {
          search: event.target.value !== 0 ? event.target.value : '',
        })
          .toPromise()
          .then((data) => {
            const markedByEntities = (
              (data as MarkingDefinitionsLinesSearchQuery$data)
                ?.markingDefinitions?.edges ?? []
            ).map((n) => ({
              label: n?.node.definition,
              value: n?.node.id,
              type: 'Marking-Definition',
              color: n?.node.x_opencti_color,
            }));
            unionSetEntities('markedBy', markedByEntities);
          });
        break;
      case 'killChainPhase':
        fetchQuery(killChainPhasesLinesSearchQuery, {
          search: event.target.value !== 0 ? event.target.value : '',
          first: 10,
        })
          .toPromise()
          .then((data) => {
            const killChainPhaseEntities = (
              (data as KillChainPhasesLinesSearchQuery$data)?.killChainPhases
                ?.edges ?? []
            ).map((n) => ({
              label: n
                ? `[${n.node.kill_chain_name}] ${n.node.phase_name}`
                : '',
              value: n?.node.id,
              type: 'Kill-Chain-Phase',
            }));
            unionSetEntities('killChainPhase', killChainPhaseEntities);
          });
        break;
      case 'labelledBy':
        fetchQuery(labelsSearchQuery, {
          search: event.target.value !== 0 ? event.target.value : '',
          first: 10,
        })
          .toPromise()
          .then((data) => {
            const labelledByEntities = (
              (data as LabelsQuerySearchQuery$data)?.labels?.edges ?? []
            ).map((n) => ({
              label: n?.node.value,
              value: n?.node.id,
              type: 'Label',
              color: n?.node.color,
            }));
            unionSetEntities('labelledBy', [
              {
                label: t('No label'),
                value: null,
                type: 'Label',
                color: theme.palette.mode === 'dark' ? '#ffffff' : '#000000',
              },
              ...labelledByEntities,
            ]);
          });
        break;
      case 'x_opencti_base_score':
        // eslint-disable-next-line no-case-declarations
        const baseScoreEntities = ['lte', 'gt'].flatMap((group) => baseScores.map((n) => ({
          label: n,
          value: n,
          type: 'Vocabulary',
          group,
        })));
        unionSetEntities('x_opencti_base_score', baseScoreEntities);
        break;
      // region confidence
      case 'confidence':
        // eslint-disable-next-line no-case-declarations
        const confidenceEntities = ['lte', 'gt'].flatMap((group) => confidences.map((n) => ({
          label: n,
          value: n,
          type: 'Vocabulary',
          group,
        })));
        unionSetEntities('confidence', confidenceEntities);
        break;
      case 'confidence_gt':
        // eslint-disable-next-line no-case-declarations
        const confidenceEntitiesGt = confidences.map((n) => ({
          label: t(`confidence_${n.toString()}`),
          value: n,
          type: 'Vocabulary',
        }));
        unionSetEntities('confidence_gt', confidenceEntitiesGt);
        break;
      case 'confidence_lte':
        // eslint-disable-next-line no-case-declarations
        const confidenceLteEntities = confidences.map((n) => ({
          label: n,
          value: n,
          type: 'Vocabulary',
        }));
        unionSetEntities('confidence_lte', confidenceLteEntities);
        break;
      // endregion
      // region likelihood
      case 'likelihood':
        // eslint-disable-next-line no-case-declarations
        const likelihoodEntities = ['lte', 'gt'].flatMap((group) => likelihoods.map((n) => ({
          label: n,
          value: n,
          type: 'Vocabulary',
          group,
        })));
        unionSetEntities('likelihood', likelihoodEntities);
        break;
      case 'likelihood_gt':
        // eslint-disable-next-line no-case-declarations
        const likelihoodEntitiesGt = likelihoods.map((n) => ({
          label: t(`likelihood_${n.toString()}`),
          value: n,
          type: 'Vocabulary',
        }));
        unionSetEntities('likelihood_gt', likelihoodEntitiesGt);
        break;
      case 'likelihood_lte':
        // eslint-disable-next-line no-case-declarations
        const likelihoodLteEntities = likelihoods.map((n) => ({
          label: n,
          value: n,
          type: 'Vocabulary',
        }));
        unionSetEntities('likelihood_lte', likelihoodLteEntities);
        break;
      // endregion
      // region x_opencti_score
      case 'x_opencti_score':
        // eslint-disable-next-line no-case-declarations
        const scoreEntities = ['lte', 'gt'].flatMap((group) => scores.map((n) => ({
          label: n,
          value: n,
          type: 'Vocabulary',
          group,
        })));
        unionSetEntities('x_opencti_score', scoreEntities);
        break;
      case 'x_opencti_score_gt':
        // eslint-disable-next-line no-case-declarations
        const scoreGtEntities = scores.map((n) => ({
          label: n,
          value: n,
          type: 'Vocabulary',
        }));
        unionSetEntities('x_opencti_score_gt', scoreGtEntities);
        break;
      case 'x_opencti_score_lte':
        // eslint-disable-next-line no-case-declarations
        const scoreLteEntities = scores.map((n) => ({
          label: n,
          value: n,
          type: 'Vocabulary',
        }));
        unionSetEntities('x_opencti_score_lte', scoreLteEntities);
        break;
      // endregion
      case 'x_opencti_detection':
        // eslint-disable-next-line no-case-declarations
        const detectionEntities = ['true', 'false'].map((n) => ({
          label: t(n),
          value: n,
          type: 'Vocabulary',
        }));
        unionSetEntities('x_opencti_detection', detectionEntities);
        break;
      case 'basedOn':
        // eslint-disable-next-line no-case-declarations
        const basedOnEntities = ['EXISTS', null].map((n) => ({
          label: n === 'EXISTS' ? t('Yes') : t('No'),
          value: n,
          type: 'Vocabulary',
        }));
        unionSetEntities('basedOn', basedOnEntities);
        break;
      case 'revoked':
        // eslint-disable-next-line no-case-declarations
        const revokedEntities = ['true', 'false'].map((n) => ({
          label: t(n),
          value: n,
          type: 'Vocabulary',
        }));
        unionSetEntities('revoked', revokedEntities);
        break;
      case 'is_read':
        // eslint-disable-next-line no-case-declarations
        const isReadEntities = ['true', 'false'].map((n) => ({
          label: t(n),
          value: n,
          type: 'Vocabulary',
        }));
        unionSetEntities('is_read', isReadEntities);
        break;
      case 'priority':
        fetchQuery(attributesSearchQuery, {
          attributeName: 'priority',
          search: event.target.value !== 0 ? event.target.value : '',
          first: 10,
        })
          .toPromise()
          .then((data) => {
            const priorityEntities = (
              (data as AttributesQuerySearchQuery$data)?.runtimeAttributes
                ?.edges ?? []
            ).map((n) => ({
              label: n?.node.value,
              value: n?.node.value,
              type: 'Vocabulary',
            }));
            unionSetEntities('priority', priorityEntities);
          });
        break;
      case 'severity':
        fetchQuery(attributesSearchQuery, {
          attributeName: 'severity',
          search: event.target.value !== 0 ? event.target.value : '',
          first: 10,
        })
          .toPromise()
          .then((data) => {
            const severityEntities = (
              (data as AttributesQuerySearchQuery$data)?.runtimeAttributes
                ?.edges ?? []
            ).map((n) => ({
              label: n?.node.value,
              value: n?.node.value,
              type: 'Vocabulary',
            }));
            unionSetEntities('severity', severityEntities);
          });
        break;
      case 'pattern_type':
        // eslint-disable-next-line no-case-declarations
        const patternTypesEntities = [
          'stix',
          'pcre',
          'sigma',
          'snort',
          'suricata',
          'yara',
          'tanium-signal',
          'spl',
          'eql',
        ].map((n) => ({
          label: t(n),
          value: n,
          type: 'Vocabulary',
        }));
        unionSetEntities('pattern_type', patternTypesEntities);
        break;
      case 'x_opencti_base_severity':
        fetchQuery(attributesSearchQuery, {
          attributeName: 'x_opencti_base_severity',
          search: event.target.value !== 0 ? event.target.value : '',
          first: 10,
        })
          .toPromise()
          .then((data) => {
            const severityEntities = (
              (data as AttributesQuerySearchQuery$data)?.runtimeAttributes
                ?.edges ?? []
            ).map((n) => ({
              label: n?.node.value,
              value: n?.node.value,
              type: 'Vocabulary',
            }));
            unionSetEntities('x_opencti_base_severity', severityEntities);
          });
        break;
      case 'x_opencti_attack_vector':
        fetchQuery(attributesSearchQuery, {
          attributeName: 'x_opencti_attack_vector',
          search: event.target.value !== 0 ? event.target.value : '',
          first: 10,
        })
          .toPromise()
          .then((data) => {
            const attackVectorEntities = (
              (data as AttributesQuerySearchQuery$data)?.runtimeAttributes
                ?.edges ?? []
            ).map((n) => ({
              label: n?.node.value,
              value: n?.node.value,
              type: 'Vocabulary',
            }));
            unionSetEntities('x_opencti_attack_vector', attackVectorEntities);
          });
        break;
      case 'malware_types':
        fetchQuery(attributesSearchQuery, {
          attributeName: 'malware_types',
          search: event.target.value !== 0 ? event.target.value : '',
          first: 10,
        })
          .toPromise()
          .then((data) => {
            const attackVectorEntities = (
              (data as AttributesQuerySearchQuery$data)?.runtimeAttributes
                ?.edges ?? []
            ).map((n) => ({
              label: n?.node.value,
              value: n?.node.value,
              type: 'Vocabulary',
            }));
            unionSetEntities('malware_types', attackVectorEntities);
          });
        break;
      case 'x_opencti_workflow_id':
        fetchQuery(statusFieldStatusesSearchQuery, {
          search: event.target.value !== 0 ? event.target.value : '',
          first: 50,
        })
          .toPromise()
          .then((data) => {
            const statusEntities = (
              (data as StatusFieldStatusesSearchQuery$data)?.statuses?.edges
              ?? []
            )
              .filter((n) => !R.isNil(n.node.template))
              .map((n) => ({
                label: n.node.template?.name,
                color: n.node.template?.color,
                value: n.node.id,
                order: n.node.order,
                group: n.node.type,
                type: 'Vocabulary',
              }));
            unionSetEntities('x_opencti_workflow_id', statusEntities);
          });
        break;
      case 'x_opencti_organization_type':
        fetchQuery(attributesSearchQuery, {
          attributeName: 'x_opencti_organization_type',
          search: event.target.value !== 0 ? event.target.value : '',
          first: 10,
        })
          .toPromise()
          .then((data) => {
            const organizationTypeEntities = (
              (data as AttributesQuerySearchQuery$data)?.runtimeAttributes
                ?.edges ?? []
            ).map((n) => ({
              label: n?.node.value,
              value: n?.node.value,
              type: 'Vocabulary',
            }));
            unionSetEntities(
              'x_opencti_organization_type',
              organizationTypeEntities,
            );
          });
        break;
      case 'source':
        fetchQuery(attributesSearchQuery, {
          attributeName: 'source',
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
            unionSetEntities('source', sourceEntities);
          });
        break;
      case 'indicator_types':
        fetchQuery(vocabularySearchQuery, {
          category: 'indicator_type_ov',
        })
          .toPromise()
          .then((data) => {
            unionSetEntities(
              'indicator_types',
              ((data as VocabularyQuery$data)?.vocabularies?.edges ?? []).map(
                ({ node }) => ({
                  label: t(node.name),
                  value: node.name,
                  type: 'Vocabulary',
                }),
              ),
            );
          });
        break;
      case 'incident_type':
        fetchQuery(vocabularySearchQuery, {
          category: 'incident_type_ov',
        })
          .toPromise()
          .then((data) => {
            unionSetEntities(
              'incident_type',
              ((data as VocabularyQuery$data)?.vocabularies?.edges ?? []).map(
                ({ node }) => ({
                  label: t(node.name),
                  value: node.name,
                  type: 'Vocabulary',
                }),
              ),
            );
          });
        break;
      case 'report_types':
        fetchQuery(vocabularySearchQuery, {
          category: 'report_types_ov',
        })
          .toPromise()
          .then((data) => {
            unionSetEntities(
              'report_types',
              ((data as VocabularyQuery$data)?.vocabularies?.edges ?? []).map(
                ({ node }) => ({
                  label: t(node.name),
                  value: node.name,
                  type: 'Vocabulary',
                }),
              ),
            );
          });
        break;
      case 'channel_types':
        fetchQuery(vocabularySearchQuery, {
          category: 'channel_types_ov',
        })
          .toPromise()
          .then((data) => {
            unionSetEntities(
              'channel_types',
              ((data as VocabularyQuery$data)?.vocabularies?.edges ?? []).map(
                ({ node }) => ({
                  label: t(node.name),
                  value: node.name,
                  type: 'Vocabulary',
                }),
              ),
            );
          });
        break;
      case 'event_types':
        fetchQuery(vocabularySearchQuery, {
          category: 'event_type_ov',
        })
          .toPromise()
          .then((data) => {
            unionSetEntities(
              'event_types',
              ((data as VocabularyQuery$data)?.vocabularies?.edges ?? []).map(
                ({ node }) => ({
                  label: t(node.name),
                  value: node.name,
                  type: 'Vocabulary',
                }),
              ),
            );
          });
        break;
      case 'context':
        fetchQuery(vocabularySearchQuery, { category: 'grouping_context_ov' })
          .toPromise()
          .then((data) => {
            unionSetEntities(
              'context',
              ((data as VocabularyQuery$data)?.vocabularies?.edges ?? []).map(
                ({ node }) => ({
                  label: t(node.name),
                  value: node.name,
                  type: 'Vocabulary',
                }),
              ),
            );
          });
        break;
      // region entity and relation types
      case 'entity_type':
      case 'entity_types':
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
          unionSetEntities('entity_type', entitiesTypes);
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
              ...result,
            ];
          }
          if (
            !availableEntityTypes
            || availableEntityTypes.includes('stix-core-relationship')
          ) {
            result = [
              ...(schema.sros ?? []).map((n) => ({
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
          unionSetEntities('entity_type', entitiesTypes);
        }
        break;
      case 'fromTypes':
        // eslint-disable-next-line no-case-declarations
        if (
          availableEntityTypes
          && !availableEntityTypes.includes('Stix-Cyber-Observable')
          && !availableEntityTypes.includes('Stix-Domain-Object')
        ) {
          const fromTypesTypes = availableEntityTypes
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
            fromTypesTypes.unshift({
              label: t('entity_All'),
              value: 'all',
              type: 'entity',
            });
          }
          unionSetEntities('fromTypes', fromTypesTypes);
        } else {
          let result = [] as EntityWithLabelValue[];
          if (
            !availableEntityTypes
            || availableEntityTypes.includes('Stix-Cyber-Observable')
          ) {
            result = [
              ...(schema.scos ?? []).map((n) => ({
                label: t(`entity_${n.label}`),
                value: n.label,
                type: n.label,
              })),
              ...result,
            ];
          }
          if (
            !availableEntityTypes
            || availableEntityTypes.includes('Stix-Domain-Object')
          ) {
            result = [
              ...(schema.sdos ?? []).map((n) => ({
                label: t(`entity_${n.label}`),
                value: n.label,
                type: n.label,
              })),
              ...result,
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
          unionSetEntities('fromTypes', entitiesTypes);
        }
        break;
      case 'toTypes':
        // eslint-disable-next-line no-case-declarations
        if (
          availableEntityTypes
          && !availableEntityTypes.includes('Stix-Cyber-Observable')
          && !availableEntityTypes.includes('Stix-Domain-Object')
        ) {
          const toTypesTypes = availableEntityTypes
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
            toTypesTypes.unshift({
              label: t('entity_All'),
              value: 'all',
              type: 'entity',
            });
          }
          unionSetEntities('toTypes', toTypesTypes);
        } else {
          let result = [] as EntityWithLabelValue[];
          if (
            !availableEntityTypes
            || availableEntityTypes.includes('Stix-Cyber-Observable')
          ) {
            result = [
              ...(schema.scos ?? []).map((n) => ({
                label: t(`entity_${n.label}`),
                value: n.label,
                type: n.label,
              })),
              ...result,
            ];
          }
          if (
            !availableEntityTypes
            || availableEntityTypes.includes('Stix-Domain-Object')
          ) {
            result = [
              ...(schema.sdos ?? []).map((n) => ({
                label: t(`entity_${n.label}`),
                value: n.label,
                type: n.label,
              })),
              ...result,
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
          unionSetEntities('toTypes', entitiesTypes);
        }
        break;
      case 'relationship_type':
        // eslint-disable-next-line no-case-declarations
        if (availableRelationshipTypes) {
          const relationshipsTypes = availableRelationshipTypes
            .map((n) => ({
              label: t(`relationship_${n.toString()}`),
              value: n,
              type: n,
            }))
            .sort((a, b) => a.label.localeCompare(b.label));
          unionSetEntities('relationship_type', relationshipsTypes);
        } else {
          const relationshipsTypes = (schema.sros ?? [])
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
          unionSetEntities('relationship_type', relationshipsTypes);
        }
        break;
      // endregion
      case 'category':
        fetchQuery(vocabCategoriesQuery)
          .toPromise()
          .then((data) => {
            unionSetEntities(
              'category',
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
      case 'container_type':
        // eslint-disable-next-line no-case-declarations
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
        unionSetEntities('container_type', containersTypes);
        break;
      case 'x_opencti_negative':
        // eslint-disable-next-line no-case-declarations
        const negativeValue = [true, false].map((n) => ({
          label: t(n ? 'False positive' : 'Malicious'),
          value: n.toString(),
          type: 'Vocabulary',
        }));
        unionSetEntities('x_opencti_negative', negativeValue);
        break;
      case 'note_types':
        fetchQuery(vocabularySearchQuery, {
          category: 'note_types_ov',
        })
          .toPromise()
          .then((data) => {
            unionSetEntities(
              'note_types',
              ((data as VocabularyQuery$data)?.vocabularies?.edges ?? []).map(
                ({ node }) => ({
                  label: t(node.name),
                  value: node.name,
                  type: 'Vocabulary',
                }),
              ),
            );
          });
        break;
      default:
        break;
    }
  };
  return [entities, searchEntities];
};

export default useSearchEntities;
