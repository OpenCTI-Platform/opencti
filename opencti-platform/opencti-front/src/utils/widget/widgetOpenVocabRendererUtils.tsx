import React from 'react';
import { Stack } from '@mui/material';
import ItemOpenVocab from '../../components/ItemOpenVocab';
import FieldOrEmpty from '../../components/FieldOrEmpty';

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
      <Stack direction="row" flexWrap="wrap" gap={1}>
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

export const openVocabSingleRenderers: Record<
  string,
  (data: Record<string, unknown>) => React.ReactElement
> = {
  priority: (d) => renderSingleOpenVocab(d, 'priority', 'case_priority_ov'),
  severity: (d) => renderSingleOpenVocab(d, 'severity', 'case_severity_ov'),
  incident_type: (d) => renderSingleOpenVocab(d, 'incident_type', 'incident_type_ov'),
  resource_level: (d) => renderSingleOpenVocab(d, 'resource_level', 'attack-resource-level-ov'),
  primary_motivation: (d) => renderSingleOpenVocab(d, 'primary_motivation', 'attack-motivation-ov'),
  x_opencti_organization_type: (d) => renderSingleOpenVocab(d, 'x_opencti_organization_type', 'organization_type_ov'),
  eye_color: (d) => renderSingleOpenVocab(d, 'eye_color', 'eye-color-ov'),
  hair_color: (d) => renderSingleOpenVocab(d, 'hair_color', 'hair-color-ov'),
};

export const openVocabListRenderers: Record<
  string,
  (data: Record<string, unknown>) => React.ReactElement
> = {
  secondary_motivations: (d) => renderOpenVocabList(d, 'secondary_motivations', 'attack-motivation-ov'),
  threat_actor_types: (d) => renderOpenVocabList(d, 'threat_actor_types', 'threat-actor-type-ov'),
  malware_types: (d) => renderOpenVocabList(d, 'malware_types', 'malware-type-ov'),
  channel_types: (d) => renderOpenVocabList(d, 'channel_types', 'channel_types_ov'),
  tool_types: (d) => renderOpenVocabList(d, 'tool_types', 'tool-type-ov'),
  note_types: (d) => renderOpenVocabList(d, 'note_types', 'note_types_ov'),
  response_types: (d) => renderOpenVocabList(d, 'response_types', 'response_types_ov'),
  information_types: (d) => renderOpenVocabList(d, 'information_types', 'information_types_ov'),
  takedown_types: (d) => renderOpenVocabList(d, 'takedown_types', 'takedown_types_ov'),
  event_types: (d) => renderOpenVocabList(d, 'event_types', 'event_types_ov'),
};
