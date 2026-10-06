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
import { canSubscriberStillAccess } from '../../graphql/subscriptionWrapper';
import { pubSubSubscription } from '../../database/redis';
import { ForbiddenAccess } from '../../config/errors';
import { ABSTRACT_STIX_CORE_RELATIONSHIP, ABSTRACT_STIX_CYBER_OBSERVABLE, ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import { ENTITY_TYPE_PIR } from '../pir/pir-types';
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
  isInvestigationRunWithheld,
  loadInvestigationRun,
  requestInvestigationEnrichment,
} from './investigationRun-domain';
import { runSourceIds } from './investigationRun-utils';
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
import { extractRepresentative } from '../../database/entity-representative';
import { ENTITY_TYPE_INVESTIGATION_POLICY, ENTITY_TYPE_INVESTIGATION_RUN, type BasicStoreEntityInvestigationRun } from './investigationRun-types';

const loadElement = (context: any, id: string | null | undefined, type: string | null | undefined) => {
  if (!id) return null;
  return context.batch.idsBatchLoader.load({ id, type: type ?? 'Basic-Object' });
};

const latestRun = (entity: { id: string }, context: any) => context.batch.latestInvestigationRunBatchLoader.load(entity.id);

// What a run derived is served to a reader only while each of its live sources
// is readable by that reader and none is restricted to authorized members,
// whichever path resolved the run: a query, a list, a case badge, the generic
// object lookup, a mutation or a subscription event. Its name quotes its
// subject, so it is withheld with the findings; its markings add those its
// sources carry now. Read once per resolved run and reader, batched across the
// runs of a page.
const servedRuns = new WeakMap<BasicStoreEntityInvestigationRun, Map<string, Promise<BasicStoreEntityInvestigationRun>>>();
const served = (run: BasicStoreEntityInvestigationRun, context: any) => {
  let byReader = servedRuns.get(run);
  if (!byReader) {
    byReader = new Map();
    servedRuns.set(run, byReader);
  }
  let view = byReader.get(context.user.id);
  if (!view) {
    view = context.batch.investigationRunServedBatchLoader.load(run) as Promise<BasicStoreEntityInvestigationRun>;
    byReader.set(context.user.id, view);
  }
  return view;
};

const artifactIdOf = (view: BasicStoreEntityInvestigationRun, key: 'draft_id' | 'workspace_id') => {
  return isInvestigationRunWithheld(view) ? null : view[key] ?? null;
};

// While what a run found is withheld from the reader, an identifier of what it
// read is served only to a reader who can read what it identifies, and the ids
// of its engine runs, which hold its findings, not at all. The stored run keeps
// them for its cleanup and its audit.
const isServedWithheld = async (run: BasicStoreEntityInvestigationRun, context: any) => isInvestigationRunWithheld(await served(run, context));
const servedSourceId = async (run: BasicStoreEntityInvestigationRun, context: any, id: string | null | undefined, type: string) => {
  if (!id || !(await isServedWithheld(run, context))) return id ?? null;
  return (await loadElement(context, id, type)) ? id : null;
};

// Where the objects a run reads and cites are published when they change, a
// marking, a sharing or a member restriction included; the PIRs it reads as
// context are internal objects, published on their own topic.
const SOURCE_EDIT_TOPICS = [
  BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].EDIT_TOPIC,
  BUS_TOPICS[ABSTRACT_STIX_CYBER_OBSERVABLE].EDIT_TOPIC,
  BUS_TOPICS[ABSTRACT_STIX_CORE_RELATIONSHIP].EDIT_TOPIC,
  BUS_TOPICS[STIX_SIGHTING_RELATIONSHIP].EDIT_TOPIC,
  BUS_TOPICS[ENTITY_TYPE_PIR].EDIT_TOPIC,
];

type RunEventPayload = { instance?: { id?: string; standard_id?: string } } | undefined;

/**
 * The events published on the topics from the moment this resolves, queued
 * until they are pulled. The redis iterator subscribes on its first pull only:
 * what is read after this call cannot miss a change published while it is read.
 */
const subscribedEvents = async <T>(topics: string[]): Promise<AsyncIterator<T>> => {
  const pending: T[] = [];
  const waiting: Array<(result: IteratorResult<T>) => void> = [];
  let open = true;
  const push = (event: T) => {
    if (!open) return;
    const pull = waiting.shift();
    if (pull) pull({ value: event, done: false });
    else pending.push(event);
  };
  const settled = await Promise.allSettled(topics.map((topic) => pubSubSubscription(topic, push)));
  const subscriptions = settled.flatMap((result) => (result.status === 'fulfilled' ? [result.value] : []));
  const close = async (): Promise<IteratorResult<T>> => {
    if (open) {
      open = false;
      subscriptions.forEach((subscription) => subscription.unsubscribe());
      waiting.splice(0).forEach((pull) => pull({ value: undefined, done: true }));
      pending.length = 0;
    }
    return { value: undefined, done: true };
  };
  const failed = settled.find((result): result is PromiseRejectedResult => result.status === 'rejected');
  if (failed) {
    await close();
    throw failed.reason;
  }
  return {
    next: () => new Promise((resolve) => {
      if (pending.length > 0) resolve({ value: pending.shift() as T, done: false });
      else if (!open) resolve({ value: undefined, done: true });
      else waiting.push(resolve);
    }),
    return: close,
    throw: async (error: Error) => {
      await close();
      throw error;
    },
  };
};

/**
 * The events of a run, and of the objects it reads and cites: a change of one
 * of them delivers the run again, so that an open view is served what the
 * subscriber may see now (findings withheld once a source is no longer
 * accessible to them) instead of keeping what it showed. The subscriber's
 * access to the run is checked on every event; what an event carries of its
 * findings is served by the run resolvers above.
 */
const subscribeToRunAndSources = async (context: any, id: string): Promise<AsyncIterable<unknown>> => {
  const item = await internalLoadById(context, context.user, id, { baseData: true, type: ENTITY_TYPE_INVESTIGATION_RUN });
  if (!item) throw ForbiddenAccess('You are not allowed to listen this.');
  const liveContext = { ...context, draft_context: '' };
  // Subscribed before the sources are read: a source changed while they are read delivers the run all the same.
  const inner = await subscribedEvents<RunEventPayload>([BUS_TOPICS[ENTITY_TYPE_INVESTIGATION_RUN].EDIT_TOPIC, ...SOURCE_EDIT_TOPICS]);
  let sources: Set<string>;
  try {
    const stored = await loadInvestigationRun(liveContext, id);
    sources = new Set(stored ? runSourceIds(stored) : []);
  } catch (error) {
    await inner.return?.();
    throw error;
  }
  // A throw here closes the socket and orphans the redis subscription: every failure skips the event.
  const runEventOf = async (payload: RunEventPayload) => {
    try {
      const instance = payload?.instance;
      if (!instance?.id) return null;
      let run: BasicStoreEntityInvestigationRun | undefined;
      if (instance.id === id) {
        run = instance as unknown as BasicStoreEntityInvestigationRun;
      } else if (sources.has(instance.id) || (!!instance.standard_id && sources.has(instance.standard_id))) {
        run = await loadInvestigationRun(liveContext, id);
      }
      if (!run) return null;
      sources = new Set(runSourceIds(run));
      return await canSubscriberStillAccess(context, run, [KNOWLEDGE]) ? { instance: run } : null;
    } catch {
      return null;
    }
  };
  const iterator = {
    next: async (): Promise<IteratorResult<unknown>> => {
      for (;;) {
        const result = await inner.next();
        if (result.done) return result;
        const event = await runEventOf(result.value);
        if (event) return { value: event, done: false };
      }
    },
    return: () => (inner.return ? inner.return() : Promise.resolve({ value: undefined, done: true })),
    throw: (error: Error) => (inner.throw ? inner.throw(error) : Promise.reject(error)),
  };
  return { [Symbol.asyncIterator]: () => iterator };
};

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
    objectMarking: async (run, _, context) => context.batch.markingsBatchLoader.load(await served(run, context)),
    subject_id: (run, _, context) => servedSourceId(run, context, run.subject_id, run.subject_type),
    subject: (run, _, context) => loadElement(context, run.subject_id, run.subject_type),
    case_id: (run, _, context) => servedSourceId(run, context, run.case_id, ENTITY_TYPE_CONTAINER_CASE),
    case: async (run, _, context) => {
      const caseIds = run.case_ids ?? [];
      if (caseIds.length === 0) return null;
      const cases = await elFindByIds<BasicStoreEntity>(context, context.user, caseIds, { type: ENTITY_TYPE_CONTAINER_CASE }) as BasicStoreEntity[];
      return (cases[0] ?? null) as any;
    },
    // The draft and the investigation graph of a withheld run hold what it
    // found: never served from it, even while their deletion is retried.
    workspace_id: async (run, _, context) => artifactIdOf(await served(run, context), 'workspace_id'),
    workspace: async (run, _, context) => {
      const id = artifactIdOf(await served(run, context), 'workspace_id');
      return id ? findWorkspaceById(context, context.user, id) : null;
    },
    draft_id: async (run, _, context) => artifactIdOf(await served(run, context), 'draft_id'),
    draft: async (run, _, context) => {
      const id = artifactIdOf(await served(run, context), 'draft_id');
      return id ? findDraftById(context, context.user, id) : null;
    },
    policy: (run, _, context) => (run.policy_id ? internalLoadById(context, context.user, run.policy_id, { type: ENTITY_TYPE_INVESTIGATION_POLICY }) : null) as any,
    runAs: (run, _, context) => context.batch.creatorBatchLoader.load(run.run_as_id),
    xtm_investigation_id: async (run, _, context) => (await isServedWithheld(run, context) ? null : run.xtm_investigation_id ?? null),
    xtm_investigation_ids: async (run, _, context) => (await isServedWithheld(run, context) ? [] : run.xtm_investigation_ids ?? []),
    xtm_revision: (run) => run.xtm_revision ?? -1,
    name: async (run, _, context) => (await served(run, context)).name,
    representative: async (run, _, context) => extractRepresentative(await served(run, context)),
    end_reason_code: async (run, _, context) => (await served(run, context)).end_reason_code ?? null,
    status_reason: async (run, _, context) => (await served(run, context)).status_reason ?? null,
    goal_plan: async (run, _, context) => (await served(run, context)).goal_plan ?? null,
    steps: async (run, _, context) => (await served(run, context)).steps ?? [],
    evidence: async (run, _, context) => (await served(run, context)).evidence ?? [],
    hypotheses: async (run, _, context) => [...((await served(run, context)).hypotheses ?? [])].sort((a, b) => a.rank - b.rank),
    timeline: async (run, _, context) => (await served(run, context)).timeline ?? [],
    recommendations: async (run, _, context) => (await served(run, context)).recommendations ?? [],
    analyst_feedback: async (run, _, context) => (await served(run, context)).analyst_feedback ?? [],
    approvals: async (run, _, context) => {
      const view = await served(run, context);
      return filterReadableRunRecords(context, context.user, view, view.approvals ?? []);
    },
    enrichment_requests: async (run, _, context) => {
      const view = await served(run, context);
      return filterReadableRunRecords(context, context.user, view, view.enrichment_requests ?? []);
    },
    enrichment_entities: async (run, _, context) => findInvestigationRunEnrichmentEntities(context, context.user, await served(run, context)),
    summary: async (run, _, context) => (await served(run, context)).summary ?? null,
    report: async (run, _, context) => (await served(run, context)).report ?? null,
    report_sources: async (run, _, context) => (await served(run, context)).report_sources ?? [],
    report_id: async (run, _, context) => (await served(run, context)).outputs?.report_id ?? null,
    can_continue: async (run, _, context) => canContinueInvestigationRun(await served(run, context)),
    budget: (run) => ({ ...run.budget, used_minutes: computeUsedMinutes(run, new Date()) }),
    acceptance: async (run, _, context) => {
      const acceptance = computeAcceptance((await served(run, context)).analyst_feedback ?? []);
      return { ...acceptance, rate: acceptanceRate(acceptance) };
    },
    report_sections: async (run, _, context) => buildInvestigationReportSections(await served(run, context)),
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
        return subscribeToRunAndSources(context, id);
      },
    },
  },
};

export default investigationRunResolvers;
