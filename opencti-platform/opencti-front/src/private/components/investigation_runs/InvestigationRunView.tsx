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

import React, { useCallback, useEffect, useMemo, useRef } from 'react';
import { graphql, useFragment, useLazyLoadQuery, useSubscription } from 'react-relay';
import type { GraphQLSubscriptionConfig } from 'relay-runtime';
import { useNavigate } from 'react-router';
import Box from '@mui/material/Box';
import Grid from '@mui/material/Grid2';
import Stack from '@mui/material/Stack';
import { useFormatter } from '../../../components/i18n';
import { fetchQuery } from '../../../relay/environment';
import InvestigationRunHeader from './InvestigationRunHeader';
import InvestigationRunApprovals from './InvestigationRunApprovals';
import InvestigationRunConclusion from './InvestigationRunConclusion';
import InvestigationRunDetails from './InvestigationRunDetails';
import InvestigationRunGoalPlan from './InvestigationRunGoalPlan';
import InvestigationRunEvidence from './InvestigationRunEvidence';
import InvestigationRunHypotheses from './InvestigationRunHypotheses';
import InvestigationRunRecommendations from './InvestigationRunRecommendations';
import InvestigationRunReport from './InvestigationRunReport';
import useGranted, { KNOWLEDGE_KNENRICHMENT, KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import { caseTabPath, consumeGraphAutoOpen, investigationGraphPath, isRunActive, reportMutationOutcome } from './investigationRunUtils';
import { InvestigationRunView_run$key } from './__generated__/InvestigationRunView_run.graphql';
import { InvestigationRunViewRunAgainMutation } from './__generated__/InvestigationRunViewRunAgainMutation.graphql';
import { InvestigationRunViewContinueMutation } from './__generated__/InvestigationRunViewContinueMutation.graphql';
import { InvestigationRunViewQuery } from './__generated__/InvestigationRunViewQuery.graphql';
import { InvestigationRunViewSubscription } from './__generated__/InvestigationRunViewSubscription.graphql';

export const investigationRunViewFragment = graphql`
  fragment InvestigationRunView_run on InvestigationRun {
    id
    name
    subject_id
    subject_type
    subject {
      id
      entity_type
      representative {
        main
      }
    }
    case_id
    case {
      id
      entity_type
      name
    }
    workspace_id
    draft_id
    draft {
      id
      name
      draft_status
      objectsCount {
        totalCount
        entitiesCount
        observablesCount
        relationshipsCount
        sightingsCount
        containersCount
      }
    }
    policy {
      id
      name
      attribution_min_confidence
      allowed_actions
    }
    pack_id
    goal_plan
    agent_slug
    xtm_investigation_id
    xtm_investigation_ids
    run_trigger
    run_status
    run_phase
    status_reason
    end_reason_code
    created_at
    started_at
    completed_at
    runAs {
      id
      name
    }
    steps {
      id
      investigation_id
      position
      action
      source_name
      status
      detail_code
      detail_params
      findings_count
      evidence_count
      started_at
      completed_at
    }
    evidence {
      id
      investigation_id
      n
      kind
      label
      href
      quote
      opencti_id
      entity_type
      in_draft
      step_id
    }
    hypotheses {
      candidate_id
      candidate_name
      candidate_type
      rationale
      rank
      score
      inconsistency
      probability
      confidence
      confidence_label
      explanation
      evidence {
        evidence_id
        evidence_type
        evidence_name
        category
        consistency
        weight
        diagnosticity
        rationale
      }
    }
    recommendations {
      id
      course_of_action_id
      text
      priority
      rationale
      action_kind
      severity
      approval_required
      status
      task_id
      courseOfAction {
        id
        name
      }
    }
    analyst_feedback {
      item_type
      item_ref
      decision
      comment
      ts
      user {
        id
        name
      }
    }
    approvals {
      id
      kind
      status
      description
      reason
      connector_id
      entity_id
      recommendation_id
      created_at
      decided_at
      rejection_reason
      decider {
        id
        name
      }
    }
    enrichment_requests {
      id
      wave_id
      entity_id
      connector_id
      connector_name
      reason
      status
      work_id
      created_at
      completed_at
    }
    enrichment_entities {
      id
      entity_type
      name
    }
    budget {
      max_iterations
      max_enrichment_jobs
      max_minutes
      used_iterations
      used_enrichment_jobs
      used_minutes
    }
    summary
    report
    report_sources {
      n
      label
      href
    }
    report_id
    can_continue
    acceptance {
      hypotheses_accepted
      hypotheses_rejected
      recommendations_accepted
      recommendations_rejected
      rate
    }
  }
`;

export const investigationRunViewQuery = graphql`
  query InvestigationRunViewQuery($id: ID!) {
    investigationRun(id: $id) {
      id
      ...InvestigationRunView_run
    }
  }
`;

const investigationRunViewRunAgainMutation = graphql`
  mutation InvestigationRunViewRunAgainMutation($subjectId: ID!, $policyId: ID, $caseId: ID) {
    investigationRunAdd(subjectId: $subjectId, policyId: $policyId, caseId: $caseId) {
      id
    }
  }
`;

const investigationRunViewContinueMutation = graphql`
  mutation InvestigationRunViewContinueMutation($id: ID!) {
    investigationRunContinue(id: $id) {
      id
      ...InvestigationRunView_run
    }
  }
`;

const investigationRunViewSubscription = graphql`
  subscription InvestigationRunViewSubscription($id: ID!) {
    investigationRun(id: $id) {
      id
      ...InvestigationRunView_run
    }
  }
`;

interface InvestigationRunContentProps {
  data: InvestigationRunView_run$key;
  currentEntityId?: string;
  onDeleted?: () => void;
  onRunStarted?: (runId: string) => void;
}

// Move the reader to a section and give it the focus, without stealing it from a control.
const reveal = (element: HTMLElement | null) => {
  if (!element) return;
  element.scrollIntoView({ behavior: 'smooth', block: 'start' });
  element.focus({ preventScroll: true });
};

const InvestigationRunContent = ({ data, currentEntityId, onDeleted, onRunStarted }: InvestigationRunContentProps) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const run = useFragment(investigationRunViewFragment, data);
  const previousStatus = useRef(run.run_status);
  const approvalsRef = useRef<HTMLDivElement>(null);
  const reportRef = useRef<HTMLDivElement>(null);
  const hypothesesRef = useRef<HTMLDivElement>(null);
  const refresh = useCallback(() => {
    fetchQuery(investigationRunViewQuery, { id: run.id }, { fetchPolicy: 'network-only' }).toPromise();
  }, [run.id]);
  useEffect(() => {
    const wasActive = isRunActive(previousStatus.current);
    previousStatus.current = run.run_status;
    if (wasActive && run.run_status === 'completed' && run.workspace_id && consumeGraphAutoOpen(run.id)) {
      navigate(investigationGraphPath(run.workspace_id));
    }
  }, [run.run_status, run.workspace_id, run.id]);
  const entityNames = useMemo(() => new Map(run.enrichment_entities.map((entity) => [entity.id, entity.name])), [run.enrichment_entities]);
  const canUpdate = useGranted([KNOWLEDGE_KNUPDATE]);
  const canEnrich = useGranted([KNOWLEDGE_KNENRICHMENT]);
  // Run again and Continue keep the policy of the run: its enrichments need the capability too.
  const canLaunch = canUpdate && (canEnrich || !run.policy?.allowed_actions.includes('enrichment'));
  const [commitRunAgain, launching] = useApiMutation<InvestigationRunViewRunAgainMutation>(investigationRunViewRunAgainMutation);
  const [commitContinue, continuing] = useApiMutation<InvestigationRunViewContinueMutation>(investigationRunViewContinueMutation);
  // Same subject and policy; the case is kept when it is live, else a new one is created in the new draft.
  const runAgain = (subjectId: string) => commitRunAgain({
    variables: { subjectId, policyId: run.policy?.id ?? null, caseId: run.case && run.case.id !== subjectId ? run.case.id : null },
    onCompleted: (response, errors) => {
      const started = response.investigationRunAdd;
      if (!started || !reportMutationOutcome(errors, t_i18n('Case Autopilot has started the investigation'))) return;
      onRunStarted?.(started.id);
    },
  });
  const continueRun = () => commitContinue({
    variables: { id: run.id },
    onCompleted: (_, errors) => {
      reportMutationOutcome(errors, t_i18n('The investigation continues'));
    },
  });
  const caseObservablesPath = run.case ? caseTabPath(run.case, 'observables') : null;
  const subjectId = run.subject_id;
  const handlers = {
    // A run that is still going cannot be launched again, nor one whose subject is withheld from the reader.
    onRunAgain: subjectId && canLaunch && !isRunActive(run.run_status) && !launching ? () => runAgain(subjectId) : undefined,
    onContinue: canLaunch && run.can_continue && !continuing ? continueRun : undefined,
    onReviewApprovals: () => reveal(approvalsRef.current),
    caseObservablesPath,
    draftPath: run.draft ? `/dashboard/data/import/draft/${run.draft.id}` : null,
  };
  return (
    <Stack spacing={3} data-testid="investigation-run-view">
      <InvestigationRunHeader
        run={run}
        handlers={handlers}
        onOpenReport={() => reveal(reportRef.current)}
        onGiveFeedback={() => reveal(hypothesesRef.current)}
        launching={launching}
        continuing={continuing}
        onDeleted={onDeleted}
      />
      <InvestigationRunApprovals ref={approvalsRef} run={run} entityNames={entityNames} onDecided={refresh} />
      <Grid container spacing={3}>
        <Grid size={{ xs: 12, lg: 8 }}>
          <InvestigationRunGoalPlan run={run} handlers={handlers} />
        </Grid>
        <Grid size={{ xs: 12, lg: 4 }}>
          <Stack spacing={3}>
            <InvestigationRunConclusion run={run} onOpenReport={() => reveal(reportRef.current)} />
            <InvestigationRunDetails run={run} currentEntityId={currentEntityId} />
          </Stack>
        </Grid>
      </Grid>
      <Box ref={hypothesesRef} tabIndex={-1} sx={{ outline: 'none' }}><InvestigationRunHypotheses run={run} /></Box>
      <InvestigationRunRecommendations run={run} />
      <InvestigationRunEvidence run={run} />
      <Box ref={reportRef} tabIndex={-1} sx={{ outline: 'none' }}><InvestigationRunReport run={run} /></Box>
    </Stack>
  );
};

interface InvestigationRunViewProps {
  runId: string;
  currentEntityId?: string;
  onDeleted?: () => void;
  onRunStarted?: (runId: string) => void;
}

/** One investigation, live: every change of the run reaches the page through the subscription. */
const InvestigationRunView = ({ runId, currentEntityId, onDeleted, onRunStarted }: InvestigationRunViewProps) => {
  const { t_i18n } = useFormatter();
  const subscriptionConfig = useMemo<GraphQLSubscriptionConfig<InvestigationRunViewSubscription>>(() => ({
    subscription: investigationRunViewSubscription,
    variables: { id: runId },
  }), [runId]);
  useSubscription(subscriptionConfig);
  const { investigationRun } = useLazyLoadQuery<InvestigationRunViewQuery>(investigationRunViewQuery, { id: runId }, { fetchPolicy: 'store-and-network' });
  if (!investigationRun) {
    return <span>{t_i18n('This investigation is no longer available.')}</span>;
  }
  return <InvestigationRunContent data={investigationRun} currentEntityId={currentEntityId} onDeleted={onDeleted} onRunStarted={onRunStarted} />;
};

export default InvestigationRunView;
