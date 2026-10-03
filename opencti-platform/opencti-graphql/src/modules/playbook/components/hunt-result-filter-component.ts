/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import type { JSONSchemaType } from 'ajv';
import { executionContext } from '../../../utils/access';
import type { PlaybookComponent } from '../playbook-types';
import { computeHuntPlaybookOutcome, findPlaybookHuntRuns, type HuntPlaybookOutcome } from '../../hunt/hunt-playbook';
import { HUNT_VERDICT_BENIGN, HUNT_VERDICT_INCONCLUSIVE, HUNT_VERDICT_PENDING, HUNT_VERDICT_TRUE_POSITIVE } from '../../hunt/huntRun/huntRun-types';

export interface HuntResultFilterConfiguration {
  verdicts: string[];
  use_triage_proposals: boolean;
  min_hits: number;
  require_incident: boolean;
}

const PLAYBOOK_HUNT_RESULT_FILTER_SCHEMA: JSONSchemaType<HuntResultFilterConfiguration> = {
  type: 'object',
  properties: {
    verdicts: {
      type: 'array',
      uniqueItems: true,
      default: [HUNT_VERDICT_TRUE_POSITIVE, HUNT_VERDICT_PENDING],
      $ref: 'Verdicts (match when a run has one of them, empty: any verdict)',
      items: {
        type: 'string',
        oneOf: [
          { const: HUNT_VERDICT_TRUE_POSITIVE, title: 'True positive' },
          { const: HUNT_VERDICT_PENDING, title: 'Pending (hits to review)' },
          { const: HUNT_VERDICT_INCONCLUSIVE, title: 'Inconclusive' },
          { const: HUNT_VERDICT_BENIGN, title: 'Benign' },
        ],
      },
    },
    use_triage_proposals: { type: 'boolean', default: true, $ref: 'Use the verdicts proposed by the triage agent for runs still pending' },
    min_hits: { type: 'number', default: 1, $ref: 'Minimum number of hits over the runs' },
    require_incident: { type: 'boolean', default: false, $ref: 'Only when an incident draft was opened' },
  },
  required: ['verdicts', 'use_triage_proposals', 'min_hits', 'require_incident'],
};

/**
 * Every configured condition must hold: a run verdict in the list (proposals of the triage agent count for pending
 * runs when enabled), at least min_hits hits, an incident draft when required. No run never matches.
 */
export const matchHuntResultFilter = (outcome: HuntPlaybookOutcome, configuration: HuntResultFilterConfiguration) => {
  if (outcome.runs_count === 0) {
    return false;
  }
  const verdicts = configuration.verdicts ?? [];
  const runVerdicts = configuration.use_triage_proposals ? outcome.proposed_verdicts : outcome.verdicts;
  const verdictMatch = verdicts.length === 0 || runVerdicts.some((verdict) => verdicts.includes(verdict));
  const hitsMatch = outcome.hits_total >= Math.max(0, configuration.min_hits ?? 0);
  const incidentMatch = !configuration.require_incident || outcome.incident_ids.length > 0;
  return verdictMatch && hitsMatch && incidentMatch;
};

export const PLAYBOOK_HUNT_RESULT_FILTER: PlaybookComponent<HuntResultFilterConfiguration> = {
  id: 'PLAYBOOK_HUNT_RESULT_FILTER',
  name: 'Match hunt results',
  description: 'Route the bundle on the outcome of the hunts run earlier in this execution (verdicts, hits, incident drafts)',
  icon: 'hunt-result',
  category: 'transform_and_enrich',
  is_entry_point: false,
  is_internal: true,
  ports: [{ id: 'out', type: 'out' }, { id: 'no-match', type: 'out' }],
  configuration_schema: PLAYBOOK_HUNT_RESULT_FILTER_SCHEMA,
  schema: async () => PLAYBOOK_HUNT_RESULT_FILTER_SCHEMA,
  executor: async ({ executionId, previousPlaybookNodeId, playbookNode, bundle }) => {
    const context = executionContext('playbook_components');
    // Directly after a hunt step: its runs; otherwise every hunt run of the execution
    const stepRuns = previousPlaybookNodeId ? await findPlaybookHuntRuns(context, executionId, previousPlaybookNodeId) : [];
    const runs = stepRuns.length > 0 ? stepRuns : await findPlaybookHuntRuns(context, executionId);
    const isMatch = matchHuntResultFilter(computeHuntPlaybookOutcome(runs), playbookNode.configuration);
    return { output_port: isMatch ? 'out' : 'no-match', bundle };
  },
};
