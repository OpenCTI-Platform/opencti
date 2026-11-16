import React from 'react';
import { Stack } from '@mui/material';
import ItemOpenVocab from '../../components/ItemOpenVocab';
import FieldOrEmpty from '../../components/FieldOrEmpty';
import type { VocabularyCategory } from '../hooks/__generated__/useVocabularyEntriesQuery.graphql';

const renderSingleOpenVocab = (
  data: Record<string, unknown>,
  attribute: string,
  vocabType: string,
) => {
  const value = data[attribute] as string | undefined;
  return (
    <ItemOpenVocab
      displayMode="chip"
      type={vocabType}
      value={value}
    />
  );
};

const renderOpenVocabList = (
  data: Record<string, unknown>,
  attribute: string,
  vocabType: string,
) => {
  const types = data[attribute] as string[] | undefined;
  return (
    <FieldOrEmpty source={types}>
      <Stack
        direction="row"
        sx={{
          flexWrap: 'wrap',
          gap: 1,
        }}
      >
        {types?.map((type) => (
          <ItemOpenVocab
            key={type}
            displayMode="chip"
            type={vocabType}
            value={type}
          />
        ))}
      </Stack>
    </FieldOrEmpty>
  );
};

// Observable types are entity types, not a vocabulary: no VocabularyCategory holds them, so their chip stays plain
type NonVocabularyType = 'observable_types_ov';

// The vocabulary of each single-value attribute: typed against the generated enum, so a name outside it fails the type check
export const openVocabSingleCategories: Record<string, VocabularyCategory | NonVocabularyType> = {
  entity_type: 'observable_types_ov',
  priority: 'case_priority_ov',
  severity: 'case_severity_ov',
  incident_type: 'incident_type_ov',
  resource_level: 'attack_resource_level_ov',
  primary_motivation: 'attack_motivation_ov',
  x_opencti_organization_type: 'organization_type_ov',
  eye_color: 'eye_color_ov',
  context: 'grouping_context_ov',
  hair_color: 'hair_color_ov',
  gender: 'gender_ov',
  marital_status: 'marital_status_ov',
  x_opencti_reliability: 'reliability_ov',
};

// The vocabulary of each multi-value attribute: typed against the generated enum, so a name outside it fails the type check
export const openVocabListCategories: Record<string, VocabularyCategory | NonVocabularyType> = {
  threat_actor_types: 'threat_actor_group_type_ov',
  malware_types: 'malware_type_ov',
  channel_types: 'channel_types_ov',
  tool_types: 'tool_types_ov',
  note_types: 'note_types_ov',
  response_types: 'incident_response_types_ov',
  information_types: 'request_for_information_types_ov',
  takedown_types: 'request_for_takedown_types_ov',
  event_types: 'event_type_ov',
  infrastructure_types: 'infrastructure_type_ov',
  architecture_execution_envs: 'processor_architecture_ov',
  implementation_languages: 'implementation_language_ov',
  capabilities: 'malware_capabilities_ov',
  indicator_types: 'indicator_type_ov',
  x_opencti_main_observable_type: 'observable_types_ov',
};

export const openVocabSingleRenderers: Record<
  string,
  (data: Record<string, unknown>) => React.ReactElement
> = Object.fromEntries(
  Object.entries(openVocabSingleCategories).map(([attribute, vocabType]) => [
    attribute,
    (d: Record<string, unknown>) => renderSingleOpenVocab(d, attribute, vocabType),
  ]),
);

export const openVocabListRenderers: Record<
  string,
  (data: Record<string, unknown>) => React.ReactElement
> = Object.fromEntries(
  Object.entries(openVocabListCategories).map(([attribute, vocabType]) => [
    attribute,
    (d: Record<string, unknown>) => renderOpenVocabList(d, attribute, vocabType),
  ]),
);
