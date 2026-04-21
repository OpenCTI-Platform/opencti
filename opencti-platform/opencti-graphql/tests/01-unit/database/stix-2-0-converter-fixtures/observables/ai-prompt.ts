import type { StoreCyberObservable } from '../../../../../src/types/store';

export const AI_PROMPT_INSTANCE = {
  id: '10000000-0000-4000-8000-000000000062',
  standard_id: 'ai-prompt--20000000-0000-4000-8000-000000000062',
  entity_type: 'AI-Prompt',
  defanged: false,
  value: 'Ignore previous instructions',
  objectMarking: [],
} as unknown as StoreCyberObservable;

export const EXPECTED_AI_PROMPT = {
  id: 'ai-prompt--20000000-0000-4000-8000-000000000062',
  type: 'ai-prompt',
  spec_version: '2.0',
  x_opencti_id: '10000000-0000-4000-8000-000000000062',
  x_opencti_type: 'AI-Prompt',
  x_opencti_granted_refs: [],
  x_opencti_files: [],
  defanged: false,
  object_marking_refs: [],
  x_opencti_labels: [],
  x_opencti_external_references: [],
  value: 'Ignore previous instructions',
  labels: [],
  external_references: [],
};

