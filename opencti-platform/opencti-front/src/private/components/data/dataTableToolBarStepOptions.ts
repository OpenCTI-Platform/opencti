import { graphql } from 'react-relay';
import { fetchQuery } from '../../../relay/environment';
import { truncate } from '../../../utils/String';
import { externalReferencesQueriesSearchQuery } from '../analyses/external_references/ExternalReferencesQueries';
import { objectAssigneeFieldMembersSearchQuery } from '../common/form/ObjectAssigneeField';
import { objectMarkingFieldAllowedMarkingsQuery } from '../common/form/ObjectMarkingField';
import { objectParticipantFieldMembersSearchQuery } from '../common/form/ObjectParticipantField';
import { vocabularyQuery } from '../common/form/OpenVocabField';
import { statusFieldStatusesSearchQuery } from '../common/form/StatusField';
import { identitySearchIdentitiesSearchQuery } from '../common/identities/IdentitySearch';
import { killChainPhasesSearchQuery } from '../settings/KillChainPhases';
import { labelsSearchQuery } from '../settings/LabelsQuery';
import type { ExternalReferencesQueriesSearchQuery$data } from '../analyses/external_references/__generated__/ExternalReferencesQueriesSearchQuery.graphql';
import type { ObjectAssigneeFieldMembersSearchQuery$data } from '../common/form/__generated__/ObjectAssigneeFieldMembersSearchQuery.graphql';
import type { ObjectMarkingFieldAllowedMarkingsQuery$data } from '../common/form/__generated__/ObjectMarkingFieldAllowedMarkingsQuery.graphql';
import type { ObjectParticipantFieldMembersSearchQuery$data } from '../common/form/__generated__/ObjectParticipantFieldMembersSearchQuery.graphql';
import type { OpenVocabFieldQuery$data } from '../common/form/__generated__/OpenVocabFieldQuery.graphql';
import type { StatusFieldStatusesSearchQuery$data } from '../common/form/__generated__/StatusFieldStatusesSearchQuery.graphql';
import type { IdentitySearchIdentitiesSearchQuery$data } from '../common/identities/__generated__/IdentitySearchIdentitiesSearchQuery.graphql';
import type { KillChainPhasesSearchQuery$data } from '../settings/__generated__/KillChainPhasesSearchQuery.graphql';
import type { LabelsQuerySearchQuery$data } from '../settings/__generated__/LabelsQuerySearchQuery.graphql';
import type { DataTableToolBarUsersLinesSearchQuery$data } from './__generated__/DataTableToolBarUsersLinesSearchQuery.graphql';
import type { dataTableToolBarStepOptionsContainersQuery$data } from './__generated__/dataTableToolBarStepOptionsContainersQuery.graphql';
import type { dataTableToolBarStepOptionsGroupsQuery$data } from './__generated__/dataTableToolBarStepOptionsGroupsQuery.graphql';

const dataTableToolBarStepOptionsContainersQuery = graphql`
  query dataTableToolBarStepOptionsContainersQuery($search: String) {
    containers(
      search: $search
      filters: {
        mode: and
        filters: [{ key: "entity_type", values: ["Container"] }]
        filterGroups: []
      }
    ) {
      edges {
        node {
          id
          entity_type
          representative {
            main
          }
        }
      }
    }
  }
`;

const dataTableToolBarStepOptionsGroupsQuery = graphql`
  query dataTableToolBarStepOptionsGroupsQuery($search: String) {
    groups(search: $search) {
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

// An option of a value field in the "Update entities" drawer
export interface StepOption {
  label: string;
  value: string;
  type?: string;
  color?: string | null;
  order?: number;
  entity?: unknown;
}

const byLabel = (a: StepOption, b: StepOption) => a.label.localeCompare(b.label);
// Sorted by label first, the stable sort keeps the labels in order inside each type
const byTypeThenLabel = (options: StepOption[]) => options.sort(byLabel).sort((a, b) => (a.type ?? '').localeCompare(b.type ?? ''));

// region mappers
export const toContainerOptions = (data: dataTableToolBarStepOptionsContainersQuery$data): StepOption[] => byTypeThenLabel(
  (data.containers?.edges ?? []).map(({ node }) => ({ label: node.representative.main, type: node.entity_type, value: node.id })),
);

export const toGroupOptions = (data: dataTableToolBarStepOptionsGroupsQuery$data): StepOption[] => byTypeThenLabel(
  (data.groups?.edges ?? []).map(({ node }) => ({ label: node.name, type: node.entity_type, value: node.id })),
);

export const toMarkingOptions = (data: ObjectMarkingFieldAllowedMarkingsQuery$data): StepOption[] => (data?.me?.allowed_marking ?? [])
  .map((n) => ({ label: n.definition ?? '', value: n.id, color: n.x_opencti_color }))
  .sort(byLabel);

export const toLabelOptions = (data: LabelsQuerySearchQuery$data): StepOption[] => (data?.labels?.edges ?? [])
  .map((n) => ({ label: n.node.value ?? '', value: n.node.id, color: n.node.color }))
  .sort(byLabel);

export const toExternalReferenceOptions = (data: ExternalReferencesQueriesSearchQuery$data): StepOption[] => (data?.externalReferences?.edges ?? [])
  .map((n) => ({
    label: `[${n.node.source_name}] ${truncate((n.node.description || n.node.external_id) as string, 150)} ${n.node.url && `(${n.node.url})`}`,
    value: n.node.id,
  }))
  .sort(byLabel);

export const toIdentityOptions = (data: IdentitySearchIdentitiesSearchQuery$data): StepOption[] => byTypeThenLabel(
  (data?.identities?.edges ?? []).map((n) => ({ label: n.node.name, value: n.node.id, type: n.node.entity_type })),
);

export const toStatusOptions = (data: StatusFieldStatusesSearchQuery$data): StepOption[] => (data?.statuses?.edges ?? [])
  .map((n) => ({ label: n.node.template?.name ?? '', value: n.node.id, order: n.node.order, color: n.node.template?.color }))
  .sort(byLabel)
  .sort((a, b) => a.order - b.order);

export const toVocabularyOptions = (data: OpenVocabFieldQuery$data): StepOption[] => (data.vocabularies?.edges ?? [])
  .map((n) => ({ label: n.node.name, value: n.node.id }));

export const toParticipantOptions = (data: ObjectParticipantFieldMembersSearchQuery$data): StepOption[] => (data.members?.edges ?? [])
  .map((n) => ({ label: n.node.name, value: n.node.id, type: n.node.entity_type }))
  .sort(byLabel);

export const toAssigneeOptions = (data: ObjectAssigneeFieldMembersSearchQuery$data): StepOption[] => (data?.members?.edges ?? [])
  .map((n) => ({ label: n.node.name, value: n.node.id, type: n.node.entity_type, entity: n.node }));

export const toUserOptions = (data: DataTableToolBarUsersLinesSearchQuery$data): StepOption[] => byTypeThenLabel(
  (data?.users?.edges ?? []).map((n) => ({ label: n.node.name, value: n.node.id, type: n.node.entity_type })),
);

export const toKillChainPhaseOptions = (data: KillChainPhasesSearchQuery$data): StepOption[] => [...(data?.killChainPhases?.edges ?? [])]
  .sort((a, b) => (a.node.x_opencti_order ?? 0) - (b.node.x_opencti_order ?? 0))
  .map((n) => ({ label: `[${n.node.kill_chain_name}] ${n.node.phase_name}`, value: n.node.id }));
// endregion

// region fetchers
const load = <T>(query: Parameters<typeof fetchQuery>[0], variables: Record<string, unknown>, toOptions: (data: T) => StepOption[]) => {
  return fetchQuery(query, variables).toPromise().then((data) => toOptions(data as T));
};

export const fetchContainerOptions = (search: string) => load(dataTableToolBarStepOptionsContainersQuery, { search }, toContainerOptions);
export const fetchGroupOptions = (search: string) => load(dataTableToolBarStepOptionsGroupsQuery, { search }, toGroupOptions);
export const fetchMarkingOptions = () => load(objectMarkingFieldAllowedMarkingsQuery, {}, toMarkingOptions);
export const fetchLabelOptions = (search: string) => load(labelsSearchQuery, { search }, toLabelOptions);
export const fetchExternalReferenceOptions = (search: string) => load(externalReferencesQueriesSearchQuery, { search }, toExternalReferenceOptions);
export const fetchIdentityOptions = (search: string) => load(
  identitySearchIdentitiesSearchQuery,
  { types: ['Individual', 'Organization', 'System'], search, first: 100 },
  toIdentityOptions,
);
export const fetchStatusOptions = (entityType: string, search: string) => load(
  statusFieldStatusesSearchQuery,
  {
    first: 100,
    filters: { mode: 'and', filterGroups: [], filters: [{ key: 'type', values: [entityType] }] },
    orderBy: 'order',
    orderMode: 'asc',
    search,
  },
  toStatusOptions,
);
export const fetchVocabularyOptions = (category: string) => load(vocabularyQuery, { category, orderBy: 'name', orderMode: 'asc' }, toVocabularyOptions);
export const fetchParticipantOptions = (search: string) => load(
  objectParticipantFieldMembersSearchQuery,
  { search, entityTypes: ['User'], first: 10 },
  toParticipantOptions,
);
export const fetchAssigneeOptions = (search: string) => load(
  objectAssigneeFieldMembersSearchQuery,
  { search, entityTypes: ['User'], first: 10 },
  toAssigneeOptions,
);
export const fetchKillChainPhaseOptions = (search: string) => load(killChainPhasesSearchQuery, { search }, toKillChainPhaseOptions);
// endregion
