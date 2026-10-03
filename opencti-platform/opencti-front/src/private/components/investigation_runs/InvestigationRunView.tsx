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
import Grid from '@mui/material/Grid2';
import Card from '@common/card/Card';
import { useFormatter } from '../../../components/i18n';
import MarkdownDisplay from '../../../components/markdownDisplay/MarkdownDisplay';
import { fetchQuery } from '../../../relay/environment';
import InvestigationRunHeader from './InvestigationRunHeader';
import InvestigationRunApprovals from './InvestigationRunApprovals';
import InvestigationRunGoalPlan from './InvestigationRunGoalPlan';
import InvestigationRunEvidence from './InvestigationRunEvidence';
import InvestigationRunHypotheses from './InvestigationRunHypotheses';
import InvestigationRunRecommendations from './InvestigationRunRecommendations';
import InvestigationRunTimeline from './InvestigationRunTimeline';
import InvestigationRunLedger from './InvestigationRunLedger';
import { consumeGraphAutoOpen, investigationGraphPath, isRunActive } from './investigationRunUtils';
import { InvestigationRunView_run$key } from './__generated__/InvestigationRunView_run.graphql';
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
    }
    policy {
      id
      name
      attribution_min_confidence
    }
    pack_id
    goal_plan
    agent_slug
    run_trigger
    run_status
    run_phase
    status_reason
    iteration
    created_at
    started_at
    completed_at
    runAs {
      id
      name
    }
    plan {
      id
      kind
      description
      status
      approval_required
    }
    steps {
      id
      step_id
      iteration
      tool
      description
      input_ref
      output_ref
      status
      started_at
      duration_ms
      cost_units
      work_id
      error
    }
    evidence {
      id
      entity_type
      name
      origin
      in_draft
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
    timeline {
      ts
      entity_id
      entity_type
      name
      event
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
    }
    enrichment_requests {
      id
      entity_id
      connector_id
      connector_name
      reason
      status
      iteration
      work_id
      created_at
      completed_at
    }
    budget {
      max_tool_calls
      max_enrichment_jobs
      max_minutes
      used_tool_calls
      used_enrichment_jobs
      used_minutes
    }
    summary
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
}

const InvestigationRunContent = ({ data, currentEntityId, onDeleted }: InvestigationRunContentProps) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const run = useFragment(investigationRunViewFragment, data);
  const previousStatus = useRef(run.run_status);
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
  const pendingApprovals = run.approvals.filter((approval) => approval.status === 'pending');
  return (
    <Grid container spacing={3} data-testid="investigation-run-view">
      <Grid size={12}>
        <InvestigationRunHeader run={run} currentEntityId={currentEntityId} onDecided={refresh} onDeleted={onDeleted} />
      </Grid>
      {pendingApprovals.length > 0 && (
        <Grid size={12}>
          <InvestigationRunApprovals runId={run.id} approvals={run.approvals} onDecided={refresh} />
        </Grid>
      )}
      <Grid size={{ xs: 12, lg: 5 }}>
        <InvestigationRunGoalPlan plan={run.plan} goalPlan={run.goal_plan} runStatus={run.run_status} />
      </Grid>
      <Grid size={{ xs: 12, lg: 7 }}>
        <Card title={t_i18n('Summary')}>
          {run.summary
            ? <MarkdownDisplay content={run.summary} remarkGfmPlugin commonmark />
            : <span>{isRunActive(run.run_status) ? t_i18n('The summary is written as the investigation progresses.') : t_i18n('No summary was produced.')}</span>}
        </Card>
      </Grid>
      <Grid size={12}>
        <InvestigationRunHypotheses run={run} />
      </Grid>
      <Grid size={12}>
        <InvestigationRunRecommendations run={run} />
      </Grid>
      <Grid size={{ xs: 12, lg: 6 }}>
        <InvestigationRunEvidence evidence={run.evidence} />
      </Grid>
      <Grid size={{ xs: 12, lg: 6 }}>
        <InvestigationRunTimeline timeline={run.timeline} />
      </Grid>
      <Grid size={12}>
        <InvestigationRunLedger steps={run.steps} enrichmentRequests={run.enrichment_requests} />
      </Grid>
    </Grid>
  );
};

interface InvestigationRunViewProps {
  runId: string;
  currentEntityId?: string;
  onDeleted?: () => void;
}

/** One investigation, live: every change of the run reaches the page through the subscription. */
const InvestigationRunView = ({ runId, currentEntityId, onDeleted }: InvestigationRunViewProps) => {
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
  return <InvestigationRunContent data={investigationRun} currentEntityId={currentEntityId} onDeleted={onDeleted} />;
};

export default InvestigationRunView;
