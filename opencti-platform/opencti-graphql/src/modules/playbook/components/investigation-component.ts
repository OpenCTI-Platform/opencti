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

import * as R from 'ramda';
import type { JSONSchemaType } from 'ajv';
import { playbookBundleElementsToApply, type PlaybookBundleElementsToApply, type PlaybookComponent } from '../playbook-types';
import { filterBundleElements, isBundleElementInScope } from '../playbook-utils';
import { logApp } from '../../../config/conf';
import { executionContext, SYSTEM_USER } from '../../../utils/access';
import { fullEntitiesList } from '../../../database/middleware-loader';
import { OPENCTI_ADMIN_UUID } from '../../../schema/general';
import { STIX_EXT_OCTI } from '../../../types/stix-2-1-extensions';
import { InvestigationRunTrigger } from '../../../generated/graphql';
import type { StixObject } from '../../../types/stix-2-1-common';
import { addInvestigationRun, investigationIdentityContext, resolveRunIdentity } from '../../investigationRun/investigationRun-domain';
import { getDefaultInvestigationPolicy, loadInvestigationPolicy } from '../../investigationRun/investigationPolicy-domain';
import { ENTITY_TYPE_INVESTIGATION_POLICY, type BasicStoreEntityInvestigationPolicy } from '../../investigationRun/investigationRun-types';
import { resolveRunAsUserId } from './ai-agent-shared';

export interface InvestigationComponentConfiguration {
  applyToElements: PlaybookBundleElementsToApply;
  applyWithFilters?: string;
  // Policy applied to the runs (budgets, gates, allowed actions); the default policy when empty.
  policy_id?: string;
  // Identity the runs act as. Same guardrail as the AI agent components: yourself or a service account.
  // The identity of the policy when empty.
  run_as?: { label: string; value: string };
}

const PLAYBOOK_INVESTIGATION_COMPONENT_SCHEMA: JSONSchemaType<InvestigationComponentConfiguration> = {
  type: 'object',
  properties: {
    applyToElements: {
      type: 'string',
      default: playbookBundleElementsToApply.onlyMain.value,
      $ref: 'Apply to',
      oneOf: [
        { const: playbookBundleElementsToApply.onlyMain.value, title: playbookBundleElementsToApply.onlyMain.title },
        { const: playbookBundleElementsToApply.allElements.value, title: playbookBundleElementsToApply.allElements.title },
        { const: playbookBundleElementsToApply.allExceptMain.value, title: playbookBundleElementsToApply.allExceptMain.title },
      ],
    },
    applyWithFilters: {
      type: 'string',
      nullable: true,
      default: '',
    },
    policy_id: {
      type: 'string',
      nullable: true,
      $ref: 'Investigation policy',
      // Populated from the investigation policies at schema() time.
      oneOf: [],
    },
    run_as: {
      type: 'object',
      $ref: 'Run as',
      nullable: true,
      default: null,
      oneOf: [],
    },
  },
  required: ['applyToElements'],
};

// STIX types a run starts from: incidents and cases.
export const INVESTIGATION_COMPATIBLE_STIX_TYPES = ['incident', 'case-incident', 'case-rfi', 'case-rft'];

const isInvestigableBundleElement = (element: StixObject) => {
  const octiType = element.extensions?.[STIX_EXT_OCTI]?.type?.toLowerCase();
  return INVESTIGATION_COMPATIBLE_STIX_TYPES.includes(element.type) || (!!octiType && INVESTIGATION_COMPATIBLE_STIX_TYPES.includes(octiType));
};

export const PLAYBOOK_INVESTIGATION_COMPONENT: PlaybookComponent<InvestigationComponentConfiguration> = {
  id: 'PLAYBOOK_INVESTIGATION_COMPONENT',
  name: 'Run Case Autopilot',
  description: 'Start a Case Autopilot investigation for each incident or case of the bundle',
  icon: 'case-autopilot',
  category: 'transform_and_enrich',
  is_entry_point: false,
  is_internal: true,
  ports: [{ id: 'out', type: 'out' }],
  configuration_schema: PLAYBOOK_INVESTIGATION_COMPONENT_SCHEMA,
  schema: async () => {
    const context = executionContext('playbook_components');
    const policies = await fullEntitiesList<BasicStoreEntityInvestigationPolicy>(context, SYSTEM_USER, [ENTITY_TYPE_INVESTIGATION_POLICY]);
    const elements = policies
      .map((policy) => ({ const: policy.internal_id, title: policy.name }))
      .sort((a, b) => a.title.localeCompare(b.title));
    return R.mergeDeepRight<JSONSchemaType<InvestigationComponentConfiguration>, any>(
      PLAYBOOK_INVESTIGATION_COMPONENT_SCHEMA,
      { properties: { policy_id: { oneOf: elements } } },
    );
  },
  executor: async ({ dataInstanceId, playbookNode, bundle, playbookId }) => {
    const context = executionContext('playbook_components');
    const { applyToElements, applyWithFilters, policy_id, run_as } = playbookNode.configuration;
    const inScope = bundle.objects.filter((object) => isBundleElementInScope(object, applyToElements, dataInstanceId));
    const elements = (await filterBundleElements(context, inScope, applyWithFilters)).filter(isInvestigableBundleElement);
    if (elements.length === 0) {
      return { output_port: 'out', bundle };
    }
    const policy = policy_id ? await loadInvestigationPolicy(context, policy_id) : await getDefaultInvestigationPolicy(context);
    if (!policy) {
      logApp.warn('[PLAYBOOK CASE AUTOPILOT] The investigation policy cannot be found, no investigation started', { playbookId, policyId: policy_id });
      return { output_port: 'out', bundle };
    }
    // Like the request for information hook: the identity configured here, else the
    // identity of the policy, else the seeded platform admin. A configured identity
    // that can no longer use the platform starts nothing, it never falls back to the
    // administrator.
    const runAsUserId = resolveRunAsUserId(run_as) || policy.run_as_id || OPENCTI_ADMIN_UUID;
    const runUser = await resolveRunIdentity(context, runAsUserId);
    if (!runUser) {
      logApp.warn('[PLAYBOOK CASE AUTOPILOT] The run-as identity cannot be resolved or can no longer use the platform, no investigation started', { playbookId, runAsUserId });
      return { output_port: 'out', bundle };
    }
    // Launched as an authenticated request of the run identity would be: organization restrictions depend on its membership.
    const runContext = await investigationIdentityContext('playbook_components', runUser);
    // One run per subject: addInvestigationRun returns the active run of a subject already investigated.
    const subjectIds = R.uniq(elements.map((element) => element.extensions?.[STIX_EXT_OCTI]?.id ?? element.id));
    for (let index = 0; index < subjectIds.length; index += 1) {
      try {
        await addInvestigationRun(runContext, runUser, subjectIds[index], policy.internal_id, { trigger: InvestigationRunTrigger.Playbook, runAsUserId: runUser.id });
      } catch (error) {
        logApp.warn('[PLAYBOOK CASE AUTOPILOT] Investigation not started', { playbookId, subjectId: subjectIds[index], cause: error });
      }
    }
    return { output_port: 'out', bundle };
  },
};
