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

import React from 'react';
import Box from '@mui/material/Box';
import Stack from '@mui/material/Stack';
import Typography from '@mui/material/Typography';
import { CheckCircleOutlined, DoNotDisturbOnOutlined, ErrorOutline, RadioButtonUncheckedOutlined, RemoveCircleOutline, WarningAmberOutlined } from '@mui/icons-material';
import { Chip, Spinner } from '@filigran/design-system';
import Card from '@common/card/Card';
import { useFormatter } from '../../../components/i18n';
import {
  buildGoalPlanView,
  ENRICHMENT_STATUS_LABELS,
  enrichmentStatusSeverity,
  goalObjective,
  type InvestigationStepStatusValue,
  isRunActive,
  stepDetail,
  stepStatusLabel,
  stepStatusSeverity,
} from './investigationRunUtils';
import type { InvestigationRunView_run$data } from './__generated__/InvestigationRunView_run.graphql';

type Step = InvestigationRunView_run$data['steps'][number];

const StepStatusIcon = ({ status, label }: { status: InvestigationStepStatusValue; label: string }) => {
  const props = { fontSize: 'small' as const, titleAccess: label };
  switch (status) {
    case 'completed':
      return <CheckCircleOutlined {...props} color="success" />;
    case 'active':
      return <Spinner size="sm" label={label} />;
    case 'error':
      return <ErrorOutline {...props} color="error" />;
    case 'degraded':
      return <WarningAmberOutlined {...props} color="warning" />;
    case 'empty':
      return <RemoveCircleOutline {...props} color="disabled" />;
    case 'skipped':
      return <DoNotDisturbOnOutlined {...props} color="disabled" />;
    default:
      return <RadioButtonUncheckedOutlined {...props} color="disabled" />;
  }
};

// Labels of the engine are English keys; one carrying a placeholder is shown as sent.
const useEngineText = () => {
  const { t_i18n } = useFormatter();
  return (value: string) => (value.includes('{') ? value : t_i18n(value));
};

const StepRow = ({ step }: { step: Step }) => {
  const { t_i18n, n } = useFormatter();
  const statusLabel = t_i18n(stepStatusLabel(step.status));
  const detail = stepDetail(step.detail_code, step.detail_params, t_i18n);
  return (
    <Stack direction="row" spacing={1.5} alignItems="flex-start" component="li" sx={{ paddingY: 0.5 }} data-testid="investigation-step">
      <Box sx={{ paddingTop: '2px', display: 'inline-flex' }}>
        <StepStatusIcon status={step.status as InvestigationStepStatusValue} label={statusLabel} />
      </Box>
      <Stack spacing={0.25} sx={{ flex: 1, minWidth: 0 }}>
        <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
          <Typography variant="body2">{step.source_name}</Typography>
          <Chip label={statusLabel} severity={stepStatusSeverity(step.status)} data-testid={`investigation-step-status-${step.status}`} />
          {step.findings_count > 0 && (
            <Typography variant="caption" color="text.secondary">{`${n(step.findings_count)} ${t_i18n('findings')}`}</Typography>
          )}
          {step.evidence_count > 0 && (
            <Typography variant="caption" color="text.secondary">{`${n(step.evidence_count)} ${t_i18n('evidence')}`}</Typography>
          )}
        </Stack>
        {detail && <Typography variant="caption" color="text.secondary">{detail}</Typography>}
      </Stack>
    </Stack>
  );
};

interface InvestigationRunGoalPlanProps {
  run: InvestigationRunView_run$data;
}

/** The goal plan of the engine: its actions in order, each with the source queries that serve it. */
const InvestigationRunGoalPlan = ({ run }: InvestigationRunGoalPlanProps) => {
  const { t_i18n } = useFormatter();
  const engineText = useEngineText();
  const view = buildGoalPlanView(run.goal_plan, run.steps);
  const done = view.actions.filter((action) => action.status === 'completed').length;
  const title = view.actions.length > 0 ? `${t_i18n('Goal plan')} (${done}/${view.actions.length})` : t_i18n('Goal plan');
  const jobs = run.enrichment_requests;
  return (
    <Card title={title}>
      <Stack spacing={2} data-testid="investigation-goal-plan">
        {view.objective && (
          <Typography variant="body2" color="text.secondary">
            {goalObjective(view.objective, run.subject?.representative.main)}
          </Typography>
        )}
        {!view.reachable && (
          <Typography variant="body2" color="warning.main">
            {t_i18n('No sequence of actions of this pack reaches the goal for this subject.')}
          </Typography>
        )}
        {view.actions.length === 0 && view.otherSteps.length === 0 && (
          <Typography variant="body2" color="text.secondary">
            {isRunActive(run.run_status) ? t_i18n('The goal plan appears once the investigation engine has started.') : t_i18n('No goal plan was produced.')}
          </Typography>
        )}
        {view.actions.length > 0 && (
          <Box component="ol" sx={{ listStyle: 'none', margin: 0, padding: 0 }}>
            {view.actions.map((action, index) => {
              const statusLabel = t_i18n(stepStatusLabel(action.status));
              return (
                <Box component="li" key={action.slug} sx={{ paddingY: 1 }} data-testid="investigation-goal-action">
                  <Stack direction="row" spacing={1.5} alignItems="flex-start">
                    <Box sx={{ paddingTop: '2px', display: 'inline-flex' }}>
                      <StepStatusIcon status={action.status} label={statusLabel} />
                    </Box>
                    <Stack spacing={0.5} sx={{ flex: 1, minWidth: 0 }}>
                      <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
                        <Typography variant="body2" sx={{ fontWeight: 600 }}>{`${index + 1}. ${engineText(action.label)}`}</Typography>
                        <Chip label={statusLabel} severity={stepStatusSeverity(action.status)} />
                        {action.producesReport && <Chip label={t_i18n('Report')} />}
                      </Stack>
                      {action.description && <Typography variant="body2" color="text.secondary">{engineText(action.description)}</Typography>}
                      {!action.servable && (
                        <Typography variant="caption" color="text.secondary">{t_i18n('No source of this investigation can serve this action.')}</Typography>
                      )}
                      {action.steps.length > 0 && (
                        <Box component="ul" sx={{ listStyle: 'none', margin: 0, padding: 0 }}>
                          {action.steps.map((step) => <StepRow key={step.id} step={step} />)}
                        </Box>
                      )}
                    </Stack>
                  </Stack>
                </Box>
              );
            })}
          </Box>
        )}
        {view.otherSteps.length > 0 && (
          <Stack spacing={0.5}>
            <Typography variant="h4">{t_i18n('Other steps')}</Typography>
            <Box component="ul" sx={{ listStyle: 'none', margin: 0, padding: 0 }}>
              {view.otherSteps.map((step) => <StepRow key={step.id} step={step} />)}
            </Box>
          </Stack>
        )}
        {jobs.length > 0 && (
          <Stack spacing={0.5} data-testid="investigation-enrichment-jobs">
            <Typography variant="h4">{`${t_i18n('Enrichment jobs')} (${jobs.length})`}</Typography>
            <Box component="ul" sx={{ listStyle: 'none', margin: 0, padding: 0 }}>
              {jobs.map((job) => (
                <Stack key={job.id} component="li" direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap sx={{ paddingY: 0.25 }}>
                  <Typography variant="body2">{job.connector_name ?? job.connector_id}</Typography>
                  <Typography variant="caption" color="text.secondary">{job.entity_id}</Typography>
                  <Chip label={t_i18n(ENRICHMENT_STATUS_LABELS[job.status] ?? job.status)} severity={enrichmentStatusSeverity(job.status)} />
                </Stack>
              ))}
            </Box>
          </Stack>
        )}
      </Stack>
    </Card>
  );
};

export default InvestigationRunGoalPlan;
