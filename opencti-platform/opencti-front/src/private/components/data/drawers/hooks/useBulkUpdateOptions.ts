import { useState } from 'react';
import * as R from 'ramda';
import {
  fetchAssigneeOptions,
  fetchExternalReferenceOptions,
  fetchGroupOptions,
  fetchIdentityOptions,
  fetchKillChainPhaseOptions,
  fetchLabelOptions,
  fetchMarkingOptions,
  fetchParticipantOptions,
  fetchStatusOptions,
  fetchVocabularyOptions,
  type StepOption,
} from '../../dataTableToolBarStepOptions';
import { fetchOrganizationOptions } from '../../dialogs/OrganizationSharingDialog';

type OptionsKey = 'markingDefinitions'
  | 'labels'
  | 'identities'
  | 'users'
  | 'organizations'
  | 'statuses'
  | 'externalReferences'
  | 'assignees'
  | 'participants'
  | 'killChainPhases'
  | 'groups';

const emptyOptions: Record<OptionsKey, StepOption[]> = {
  markingDefinitions: [],
  labels: [],
  identities: [],
  users: [],
  organizations: [],
  statuses: [],
  externalReferences: [],
  assignees: [],
  participants: [],
  killChainPhases: [],
  groups: [],
};

const emptyVocabularies: Record<string, StepOption[]> = {
  case_severity_ov: [],
  case_priority_ov: [],
  incident_response_types_ov: [],
  request_for_information_types_ov: [],
  request_for_takedown_types_ov: [],
  indicator_type_ov: [],
  platforms_ov: [],
};

const searchText = (newValue: string | null | undefined) => (newValue && newValue.length > 0 ? newValue : '');

// The options of the values fields of the "Update entities" drawer, loaded when a field is searched.
// Some fields keep the options already loaded and add the new ones.
const useBulkUpdateOptions = (
  setInputValue: (i: number, newValue: string) => void,
  fetchUserOptions: (search: string) => Promise<StepOption[]>,
) => {
  const [options, setOptions] = useState(emptyOptions);
  const [vocabularies, setVocabularies] = useState(emptyVocabularies);

  const searchStepOptions = (
    i: number,
    newValue: string,
    key: OptionsKey,
    loadOptions: (search: string) => Promise<StepOption[]>,
    keepPrevious = false,
  ) => {
    setInputValue(i, newValue);
    loadOptions(searchText(newValue)).then((loaded) => {
      setOptions((current) => ({ ...current, [key]: keepPrevious ? R.union(current[key], loaded) : loaded }));
    });
  };

  const search = {
    groups: (i: number, newValue: string) => searchStepOptions(i, newValue, 'groups', fetchGroupOptions),
    organizations: (i: number, newValue: string) => searchStepOptions(i, newValue, 'organizations', fetchOrganizationOptions),
    markingDefinitions: (i: number, newValue: string) => searchStepOptions(i, newValue, 'markingDefinitions', fetchMarkingOptions),
    labels: (i: number, newValue: string) => searchStepOptions(i, newValue, 'labels', fetchLabelOptions, true),
    externalReferences: (i: number, newValue: string) => searchStepOptions(i, newValue, 'externalReferences', fetchExternalReferenceOptions, true),
    identities: (i: number, newValue: string) => searchStepOptions(i, newValue, 'identities', fetchIdentityOptions, true),
    participants: (i: number, newValue: string) => searchStepOptions(i, newValue, 'participants', fetchParticipantOptions, true),
    assignees: (i: number, newValue: string) => searchStepOptions(i, newValue, 'assignees', fetchAssigneeOptions, true),
    users: (i: number, newValue: string) => searchStepOptions(i, newValue, 'users', fetchUserOptions, true),
    killChainPhases: (i: number, newValue: string) => searchStepOptions(i, newValue, 'killChainPhases', fetchKillChainPhaseOptions, true),
    accountStatus: (i: number, newValue: string) => setInputValue(i, newValue),
    statuses: (i: number, selectedTypes: string[], newValue: string) => {
      if (selectedTypes.length !== 1) {
        throw Error('It is not possible to bulk edit statuses if more than one entity type is selected.');
      }
      searchStepOptions(i, newValue, 'statuses', (text) => fetchStatusOptions(selectedTypes[0], text), true);
    },
    vocabulary: (i: number, category: string, newValue: string) => {
      setInputValue(i, newValue);
      fetchVocabularyOptions(category).then((loaded) => {
        setVocabularies((current) => ({ ...current, [category]: R.union(current[category] || [], loaded) }));
      });
    },
  };

  return { options, vocabularies, search };
};

export default useBulkUpdateOptions;
