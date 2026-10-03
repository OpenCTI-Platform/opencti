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

import React, { useState } from 'react';
import Box from '@mui/material/Box';
import Stack from '@mui/material/Stack';
import Typography from '@mui/material/Typography';
import {
  CheckCircleOutlined,
  ErrorOutline,
  ExpandLessOutlined,
  ExpandMoreOutlined,
  RemoveCircleOutline,
  ScheduleOutlined,
  SkipNextOutlined,
  WarningAmberOutlined,
} from '@mui/icons-material';
import { Chip, Spinner } from '@filigran/design-system';
import Card from '@common/card/Card';
import Button from '@common/button/Button';
import { useFormatter } from '../../../components/i18n';
import InvestigationRunEvidenceItem from './InvestigationRunEvidenceItem';
import InvestigationRunStepOutcome, { type StepActionHandlers } from './InvestigationRunStepNextAction';
import {
  buildGoalPlanView,
  citationNumbers,
  ENRICHMENT_STATUS_LABELS,
  enrichmentStatusSeverity,
  type GoalPlanAction,
  goalObjective,
  type InvestigationStepStatusValue,
  isEngineRunOver,
  isRunActive,
  stepStatusLabel,
  stepStatusSeverity,
} from './investigationRunUtils';
import { elapsedMs, formatDuration, stepOutcome, type Translate } from './investigationRunOutcomes';
import type { InvestigationRunView_run$data } from './__generated__/InvestigationRunView_run.graphql';

type Run = InvestigationRunView_run$data;
type Step = Run['steps'][number];
type Evidence = Run['evidence'][number];

// Order of the counters above the stepper: what needs attention first.
const COUNTER_ORDER: InvestigationStepStatusValue[] = ['error', 'degraded', 'active', 'completed', 'empty', 'skipped', 'pending'];

const COUNTER_LABELS: Record<InvestigationStepStatusValue, string> = {
  error: '{count} failed',
  degraded: '{count} partial',
  active: '{count} querying',
  completed: '{count} found',
  empty: '{count} nothing found',
  skipped: '{count} not reached',
  pending: '{count} planned',
};

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
      return <RemoveCircleOutline {...props} color="action" />;
    case 'skipped':
      return <SkipNextOutlined {...props} color="disabled" />;
    default:
      return <ScheduleOutlined {...props} color="action" />;
  }
};

const outcomeTone = (status: string): 'secondary' | 'warning' | 'error' => {
  if (status === 'error') return 'error';
  if (status === 'degraded') return 'warning';
  return 'secondary';
};

// Labels of the engine are English keys; one carrying a placeholder is shown as sent.
const engineText = (value: string, t: Translate) => (value.includes('{') ? value : t(value));

/** Duration of a set of steps, from the first start to the last end (or now while one runs). */
const stepsDuration = (steps: readonly Step[]) => {
  const starts = steps.map((step) => step.started_at).filter((value): value is string => !!value).sort();
  if (starts.length === 0) return null;
  const running = steps.some((step) => step.status === 'active' || (step.started_at && !step.completed_at));
  const ends = steps.map((step) => step.completed_at).filter((value): value is string => !!value).sort();
  return elapsedMs(starts[0], running ? null : ends[ends.length - 1]);
};

const StepMeta = ({ steps, evidenceCount }: { steps: readonly Step[]; evidenceCount: number }) => {
  const { t_i18n } = useFormatter();
  const duration = stepsDuration(steps);
  const findings = steps.reduce((total, step) => total + step.findings_count, 0);
  const parts = [
    duration !== null ? formatDuration(duration, t_i18n) : null,
    findings > 0 ? t_i18n('{count, plural, one {# finding} other {# findings}}', { values: { count: findings } }) : null,
    evidenceCount > 0 ? t_i18n('{count} evidence', { values: { count: evidenceCount } }) : null,
  ].filter((part): part is string => !!part);
  if (parts.length === 0) return null;
  return (
    <Typography variant="caption" color="text.secondary" sx={{ whiteSpace: 'nowrap', fontVariantNumeric: 'tabular-nums' }}>
      {parts.join(' - ')}
    </Typography>
  );
};

interface SourceRowProps {
  step: Step;
  handlers: StepActionHandlers;
}

const SourceRow = ({ step, handlers }: SourceRowProps) => {
  const { t_i18n } = useFormatter();
  const statusLabel = t_i18n(stepStatusLabel(step.status));
  const outcome = stepOutcome(step.status, step.detail_code, step.detail_params, t_i18n);
  return (
    <Stack component="li" spacing={0.5} sx={{ paddingY: 0.75 }} data-testid="investigation-step">
      <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
        <StepStatusIcon status={step.status as InvestigationStepStatusValue} label={statusLabel} />
        <Typography variant="body2" sx={{ minWidth: 0, overflowWrap: 'anywhere' }}>{step.source_name}</Typography>
        <Chip label={statusLabel} severity={stepStatusSeverity(step.status)} size="sm" data-testid={`investigation-step-status-${step.status}`} />
        <Box sx={{ flex: 1 }} />
        <StepMeta steps={[step]} evidenceCount={step.evidence_count} />
      </Stack>
      {outcome && step.status !== 'completed' && (
        <Box sx={{ paddingLeft: 3.5 }}>
          <InvestigationRunStepOutcome outcome={outcome} tone={outcomeTone(step.status)} handlers={handlers} />
        </Box>
      )}
    </Stack>
  );
};

interface StepperItemProps {
  index: number;
  title: string;
  description: string | null;
  status: InvestigationStepStatusValue;
  steps: readonly Step[];
  evidence: readonly Evidence[];
  numbers: Map<string, number>;
  isLast: boolean;
  open: boolean;
  onToggle: () => void;
  note: string | null;
  handlers: StepActionHandlers;
  itemId: string;
}

const StepperItem = ({ index, title, description, status, steps, evidence, numbers, isLast, open, onToggle, note, handlers, itemId }: StepperItemProps) => {
  const { t_i18n } = useFormatter();
  const statusLabel = t_i18n(stepStatusLabel(status));
  const evidenceCount = Math.max(evidence.length, steps.reduce((total, step) => total + step.evidence_count, 0));
  const panelId = `investigation-goal-action-panel-${itemId}`;
  // A single source with nothing to explain needs no expanded detail beyond its evidence.
  const expandable = steps.length > 0 || evidence.length > 0;
  // What a step without source says about itself: never a bare state.
  const ownOutcome = steps.length === 0 ? stepOutcome(status, null, null, t_i18n) : null;
  return (
    <Box component="li" sx={{ display: 'flex', gap: 1.5 }} data-testid="investigation-goal-action" data-status={status}>
      <Stack alignItems="center" sx={{ width: 24, flexShrink: 0 }}>
        <Box sx={{ height: 24, display: 'inline-flex', alignItems: 'center' }}>
          <StepStatusIcon status={status} label={statusLabel} />
        </Box>
        {!isLast && <Box sx={{ flex: 1, width: '1px', minHeight: 16, backgroundColor: 'divider', marginTop: 0.5 }} aria-hidden />}
      </Stack>
      <Stack spacing={0.75} sx={{ flex: 1, minWidth: 0, paddingBottom: isLast ? 0 : 2.5 }}>
        <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap sx={{ minHeight: 24 }}>
          <Typography variant="body2" sx={{ fontWeight: 600, overflowWrap: 'anywhere' }}>{`${index}. ${title}`}</Typography>
          <Chip label={statusLabel} severity={stepStatusSeverity(status)} size="sm" />
          <Box sx={{ flex: 1 }} />
          <StepMeta steps={steps} evidenceCount={evidenceCount} />
          {expandable && (
            <Button
              size="small"
              variant="tertiary"
              onClick={onToggle}
              aria-expanded={open}
              aria-controls={panelId}
              aria-label={open ? t_i18n('Collapse the step {name}', { values: { name: title } }) : t_i18n('Expand the step {name}', { values: { name: title } })}
              startIcon={open ? <ExpandLessOutlined fontSize="small" /> : <ExpandMoreOutlined fontSize="small" />}
            >
              {open ? t_i18n('Hide') : t_i18n('Details')}
            </Button>
          )}
        </Stack>
        {description && <Typography variant="body2" color="text.secondary">{description}</Typography>}
        {note && <Typography variant="caption" color="text.secondary">{note}</Typography>}
        {ownOutcome && status !== 'pending' && status !== 'active' && (
          <InvestigationRunStepOutcome outcome={ownOutcome} tone={outcomeTone(status)} handlers={handlers} />
        )}
        {open && expandable && (
          <Stack id={panelId} spacing={1} sx={{ paddingTop: 0.5 }}>
            {steps.length > 0 && (
              <Box component="ul" sx={{ listStyle: 'none', margin: 0, padding: 0 }} aria-label={t_i18n('Sources of the step')}>
                {steps.map((step) => <SourceRow key={step.id} step={step} handlers={handlers} />)}
              </Box>
            )}
            {evidence.length > 0 && (
              <Box component="ol" sx={{ listStyle: 'none', margin: 0, padding: 0 }} aria-label={t_i18n('Evidence of the step')}>
                {evidence.map((item) => <InvestigationRunEvidenceItem key={item.id} item={item} number={numbers.get(item.id)} />)}
              </Box>
            )}
          </Stack>
        )}
      </Stack>
    </Box>
  );
};

/** Steps open by default: the one running and every one that needs attention; found ones stay collapsed in long plans. */
const isOpenByDefault = (status: InvestigationStepStatusValue, actionCount: number) => {
  if (status === 'active' || status === 'error' || status === 'degraded') return true;
  return actionCount <= 3 && status !== 'pending' && status !== 'skipped';
};

interface InvestigationRunGoalPlanProps {
  run: Run;
  handlers: StepActionHandlers;
  entityNames: Map<string, string>;
}

/** The goal plan of the engine as a stepper: each action with its state, duration, counts, sources and evidence. */
const InvestigationRunGoalPlan = ({ run, handlers, entityNames }: InvestigationRunGoalPlanProps) => {
  const { t_i18n } = useFormatter();
  const [filter, setFilter] = useState<InvestigationStepStatusValue | null>(null);
  const [overrides, setOverrides] = useState<Record<string, boolean>>({});
  const view = buildGoalPlanView(run.goal_plan, run.steps, isEngineRunOver(run));
  const numbers = citationNumbers(run.evidence);
  const evidenceOf = (steps: readonly Step[]) => {
    const ids = new Set(steps.map((step) => step.id));
    return run.evidence.filter((item) => item.step_id && ids.has(item.step_id))
      .sort((a, b) => (numbers.get(a.id) ?? 0) - (numbers.get(b.id) ?? 0));
  };
  const total = view.actions.length;
  const done = view.actions.filter((action) => !['pending', 'active'].includes(action.status)).length;
  const counts = COUNTER_ORDER.map((status) => ({ status, count: view.actions.filter((action) => action.status === status).length }))
    .filter((counter) => counter.count > 0);
  const visibleActions = filter ? view.actions.filter((action) => action.status === filter) : view.actions;
  const isOpen = (key: string, status: InvestigationStepStatusValue) => overrides[key] ?? isOpenByDefault(status, total);
  const toggle = (key: string, status: InvestigationStepStatusValue) => setOverrides({ ...overrides, [key]: !isOpen(key, status) });
  const actionNote = (action: GoalPlanAction<Step>) => {
    if (!action.servable) return t_i18n('No source of this investigation can serve this action.');
    if (action.producesReport) return t_i18n('This step writes the report.');
    return null;
  };
  const jobs = run.enrichment_requests;
  const title = total > 0
    ? t_i18n('Goal plan - {done} of {total} steps done', { values: { done, total } })
    : t_i18n('Goal plan');
  return (
    <Card title={title}>
      <Stack spacing={2} data-testid="investigation-goal-plan">
        {view.objective && (
          <Typography variant="body2" color="text.secondary">{goalObjective(engineText(view.objective, t_i18n), run.subject?.representative.main)}</Typography>
        )}
        {!view.reachable && (
          <Typography variant="body2" color="warning.main">
            {t_i18n('No sequence of actions of this pack reaches the goal for this subject.')}
          </Typography>
        )}
        {counts.length > 1 && (
          <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap role="group" aria-label={t_i18n('Filter the steps by state')}>
            {counts.map(({ status, count }) => (
              <Button
                key={status}
                size="small"
                variant={filter === status ? 'secondary' : 'tertiary'}
                aria-pressed={filter === status}
                onClick={() => setFilter(filter === status ? null : status)}
                data-testid={`investigation-goal-counter-${status}`}
              >
                {t_i18n(COUNTER_LABELS[status], { values: { count } })}
              </Button>
            ))}
            {filter && <Button size="small" variant="tertiary" onClick={() => setFilter(null)}>{t_i18n('Show all steps')}</Button>}
          </Stack>
        )}
        {total === 0 && view.otherSteps.length === 0 && (
          <Typography variant="body2" color="text.secondary">
            {isRunActive(run.run_status) ? t_i18n('The goal plan appears once the investigation engine has started.') : t_i18n('No goal plan was produced.')}
          </Typography>
        )}
        {visibleActions.length > 0 && (
          <Box component="ol" sx={{ listStyle: 'none', margin: 0, padding: 0 }} aria-label={t_i18n('Goal plan')}>
            {visibleActions.map((action, index) => (
              <StepperItem
                key={action.slug}
                itemId={String(view.actions.indexOf(action) + 1)}
                index={view.actions.indexOf(action) + 1}
                title={engineText(action.label, t_i18n)}
                description={action.description ? engineText(action.description, t_i18n) : null}
                status={action.status}
                steps={action.steps}
                evidence={evidenceOf(action.steps)}
                numbers={numbers}
                isLast={index === visibleActions.length - 1 && (filter !== null || view.otherSteps.length === 0)}
                open={isOpen(action.slug, action.status)}
                onToggle={() => toggle(action.slug, action.status)}
                note={actionNote(action)}
                handlers={handlers}
              />
            ))}
          </Box>
        )}
        {!filter && view.otherSteps.length > 0 && (
          <Stack spacing={0.5}>
            <Typography variant="h4">{t_i18n('Other steps')}</Typography>
            <Box component="ul" sx={{ listStyle: 'none', margin: 0, padding: 0 }}>
              {view.otherSteps.map((step) => <SourceRow key={step.id} step={step} handlers={handlers} />)}
            </Box>
          </Stack>
        )}
        {jobs.length > 0 && (
          <Stack spacing={0.5} data-testid="investigation-enrichment-jobs">
            <Typography variant="h4">{t_i18n('Enrichment jobs ({count})', { values: { count: jobs.length } })}</Typography>
            <Box component="ul" sx={{ listStyle: 'none', margin: 0, padding: 0 }}>
              {jobs.map((job) => (
                <Stack key={job.id} component="li" direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap sx={{ paddingY: 0.5 }}>
                  <Typography variant="body2">
                    {t_i18n('{connector} on {entity}', {
                      values: {
                        connector: job.connector_name ?? t_i18n('An enrichment connector'),
                        entity: entityNames.get(job.entity_id) ?? t_i18n('a restricted entity'),
                      },
                    })}
                  </Typography>
                  <Chip label={t_i18n(ENRICHMENT_STATUS_LABELS[job.status] ?? 'Queued')} severity={enrichmentStatusSeverity(job.status)} size="sm" />
                  {job.completed_at && (
                    <Typography variant="caption" color="text.secondary">
                      {formatDuration(elapsedMs(job.created_at, job.completed_at) ?? 0, t_i18n)}
                    </Typography>
                  )}
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
