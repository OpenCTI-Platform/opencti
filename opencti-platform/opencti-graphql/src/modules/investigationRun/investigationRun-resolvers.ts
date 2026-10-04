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

import type { Resolvers } from '../../generated/graphql';
import { BUS_TOPICS } from '../../config/conf';
import { checkEnterpriseEdition } from '../../enterprise-edition/ee';
import { subscribeToInstanceEvents } from '../../graphql/subscriptionWrapper';
import { KNOWLEDGE } from '../../utils/access';
import { loadCreators } from '../../database/members';
import { elFindByIds } from '../../database/engine';
import { internalLoadById } from '../../database/middleware-loader';
import type { BasicStoreEntity } from '../../types/store';
import { ENTITY_TYPE_CONTAINER_CASE } from '../case/case-types';
import { ENTITY_TYPE_COURSE_OF_ACTION } from '../../schema/stixDomainObject';
import { findById as findWorkspaceById } from '../workspace/workspace-domain';
import { findById as findDraftById } from '../draftWorkspace/draftWorkspace-domain';
import {
  addInvestigationRun,
  addInvestigationRunFeedback,
  applyInvestigationRecommendation,
  canContinueInvestigationRun,
  cancelInvestigationRun,
  continueInvestigationRun,
  deleteInvestigationRun,
  findInvestigationPackCatalog,
  findInvestigationRunById,
  findInvestigationRunEnrichmentEntities,
  findInvestigationRunEnrichmentWave,
  findInvestigationRunsPaginated,
  filterReadableRunRecords,
  requestInvestigationEnrichment,
} from './investigationRun-domain';
import {
  addInvestigationPolicy,
  countInvestigationRunsForPolicy,
  deleteInvestigationPolicy,
  editInvestigationPolicy,
  findInvestigationPoliciesPaginated,
  findInvestigationPolicyById,
  listInvestigationEnrichmentConnectors,
} from './investigationPolicy-domain';
import { acceptanceRate, computeAcceptance, computeUsedMinutes } from './investigationRun-state';
import { buildInvestigationReportSections } from './investigationRun-report';
import { ENTITY_TYPE_INVESTIGATION_POLICY, ENTITY_TYPE_INVESTIGATION_RUN, type BasicStoreEntityInvestigationRun } from './investigationRun-types';

const loadElement = (context: any, id: string | null | undefined, type: string | null | undefined) => {
  if (!id) return null;
  return context.batch.idsBatchLoader.load({ id, type: type ?? 'Basic-Object' });
};

const latestRun = (entity: { id: string }, context: any) => context.batch.latestInvestigationRunBatchLoader.load(entity.id);

const investigationRunResolvers: Resolvers = {
  Query: {
    investigationRun: (_, { id }, context) => findInvestigationRunById(context, context.user, id),
    investigationRuns: (_, args, context) => findInvestigationRunsPaginated(context, context.user, args),
    investigationRunEnrichmentWave: (_, { id, waveId }, context) => findInvestigationRunEnrichmentWave(context, context.user, id, waveId),
    investigationPacks: (_, __, context) => findInvestigationPackCatalog(context, context.user),
    investigationPolicy: (_, { id }, context) => findInvestigationPolicyById(context, context.user, id),
    investigationPolicies: (_, args, context) => findInvestigationPoliciesPaginated(context, context.user, args),
    investigationEnrichmentConnectors: (_, __, context) => listInvestigationEnrichmentConnectors(context, context.user),
  },
  InvestigationRun: {
    creators: (run, _, context) => loadCreators(context, context.user, run),
    objectMarking: (run, _, context) => context.batch.markingsBatchLoader.load(run),
    subject: (run, _, context) => loadElement(context, run.subject_id, run.subject_type),
    case: async (run, _, context) => {
      const caseIds = run.case_ids ?? [];
      if (caseIds.length === 0) return null;
      const cases = await elFindByIds<BasicStoreEntity>(context, context.user, caseIds, { type: ENTITY_TYPE_CONTAINER_CASE }) as BasicStoreEntity[];
      return (cases[0] ?? null) as any;
    },
    workspace: (run, _, context) => (run.workspace_id ? findWorkspaceById(context, context.user, run.workspace_id) : null),
    draft: (run, _, context) => (run.draft_id ? findDraftById(context, context.user, run.draft_id) : null),
    policy: (run, _, context) => (run.policy_id ? internalLoadById(context, context.user, run.policy_id, { type: ENTITY_TYPE_INVESTIGATION_POLICY }) : null) as any,
    runAs: (run, _, context) => context.batch.creatorBatchLoader.load(run.run_as_id),
    xtm_investigation_ids: (run) => run.xtm_investigation_ids ?? [],
    xtm_revision: (run) => run.xtm_revision ?? -1,
    steps: (run) => run.steps ?? [],
    evidence: (run) => run.evidence ?? [],
    hypotheses: (run) => [...(run.hypotheses ?? [])].sort((a, b) => a.rank - b.rank),
    timeline: (run) => run.timeline ?? [],
    recommendations: (run) => run.recommendations ?? [],
    analyst_feedback: (run) => run.analyst_feedback ?? [],
    approvals: (run, _, context) => filterReadableRunRecords(context, context.user, run, run.approvals ?? []),
    enrichment_requests: (run, _, context) => filterReadableRunRecords(context, context.user, run, run.enrichment_requests ?? []),
    enrichment_entities: (run, _, context) => findInvestigationRunEnrichmentEntities(context, context.user, run),
    report_sources: (run) => run.report_sources ?? [],
    report_id: (run) => run.outputs?.report_id ?? null,
    can_continue: (run) => canContinueInvestigationRun(run),
    budget: (run) => ({ ...run.budget, used_minutes: computeUsedMinutes(run, new Date()) }),
    acceptance: (run) => {
      const acceptance = computeAcceptance(run.analyst_feedback ?? []);
      return { ...acceptance, rate: acceptanceRate(acceptance) };
    },
    report_sections: (run) => buildInvestigationReportSections(run),
  },
  InvestigationHypothesis: {
    candidate: (hypothesis, _, context) => loadElement(context, hypothesis.candidate_id, hypothesis.candidate_type),
  },
  InvestigationRecommendation: {
    courseOfAction: (recommendation, _, context) => loadElement(context, recommendation.course_of_action_id, ENTITY_TYPE_COURSE_OF_ACTION),
  },
  InvestigationFeedback: {
    user: (feedback, _, context) => context.batch.creatorBatchLoader.load(feedback.user_id),
  },
  InvestigationApproval: {
    decider: (approval, _, context) => (approval.decided_by ? context.batch.creatorBatchLoader.load(approval.decided_by) : null),
  },
  InvestigationPolicy: {
    creators: (policy, _, context) => loadCreators(context, context.user, policy),
    runAs: (policy, _, context) => (policy.run_as_id ? context.batch.creatorBatchLoader.load(policy.run_as_id) : null),
    allowed_actions: (policy) => policy.allowed_actions ?? [],
    enrichment_connector_ids: (policy) => policy.enrichment_connector_ids ?? [],
    approval_connector_ids: (policy) => policy.approval_connector_ids ?? [],
    runs_count: (policy, _, context) => countInvestigationRunsForPolicy(context, context.user, policy.internal_id),
    acceptance: (policy) => {
      const acceptance = {
        hypotheses_accepted: policy.hypotheses_accepted ?? 0,
        hypotheses_rejected: policy.hypotheses_rejected ?? 0,
        recommendations_accepted: policy.recommendations_accepted ?? 0,
        recommendations_rejected: policy.recommendations_rejected ?? 0,
      };
      return { ...acceptance, rate: acceptanceRate(acceptance) };
    },
  },
  CaseIncident: { latestInvestigationRun: (entity, _, context) => latestRun(entity, context) },
  CaseRfi: { latestInvestigationRun: (entity, _, context) => latestRun(entity, context) },
  CaseRft: { latestInvestigationRun: (entity, _, context) => latestRun(entity, context) },
  Feedback: { latestInvestigationRun: (entity, _, context) => latestRun(entity, context) },
  Incident: { latestInvestigationRun: (entity, _, context) => latestRun(entity, context) },
  Mutation: {
    investigationRunAdd: (_, { subjectId, policyId, caseId }, context) => addInvestigationRun(context, context.user, subjectId, policyId, { caseId }),
    investigationRunCancel: (_, { id }, context) => cancelInvestigationRun(context, context.user, id),
    investigationRunContinue: (_, { id }, context) => continueInvestigationRun(context, context.user, id),
    investigationRunDelete: (_, { id }, context) => deleteInvestigationRun(context, context.user, id),
    investigationRunFeedback: (_, { id, input }, context) => addInvestigationRunFeedback(context, context.user, id, input),
    investigationRunRecommendationApply: (_, { id, recommendationId, mode }, context) => applyInvestigationRecommendation(context, context.user, id, recommendationId, mode),
    investigationRunEnrichmentRequest: (_, { id, input }, context) => requestInvestigationEnrichment(context, context.user, id, input),
    investigationPolicyAdd: (_, { input }, context) => addInvestigationPolicy(context, context.user, input),
    investigationPolicyFieldPatch: (_, { id, input }, context) => editInvestigationPolicy(context, context.user, id, input),
    investigationPolicyDelete: (_, { id }, context) => deleteInvestigationPolicy(context, context.user, id),
  },
  Subscription: {
    investigationRun: {
      resolve: (payload: { instance: BasicStoreEntityInvestigationRun }) => payload.instance,
      subscribe: async (_: unknown, { id }: { id: string }, context: any) => {
        await checkEnterpriseEdition(context);
        const bus = BUS_TOPICS[ENTITY_TYPE_INVESTIGATION_RUN];
        // A run's markings widen as it cites restricted objects: access is checked on every event.
        return subscribeToInstanceEvents(_, context, id, [bus.EDIT_TOPIC], {
          type: ENTITY_TYPE_INVESTIGATION_RUN,
          notifySelf: true,
          recheckAccess: true,
          requiredCapabilities: [KNOWLEDGE],
        });
      },
    },
  },
};

export default investigationRunResolvers;
