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
import { CheckCircleOutlined, ErrorOutline, PanToolOutlined, RadioButtonUncheckedOutlined, RemoveCircleOutline } from '@mui/icons-material';
import { Chip, Spinner } from '@filigran/design-system';
import Card from '@common/card/Card';
import { useFormatter } from '../../../components/i18n';
import { type GoalPlanItem, type GoalStatus, goalsFromGoalPlan, goalsFromPlan, isRunActive, PLAN_STEP_KIND_LABELS } from './investigationRunUtils';
import type { InvestigationRunView_run$data } from './__generated__/InvestigationRunView_run.graphql';

const GOAL_STATUS_LABELS: Record<GoalStatus, string> = {
  pending: 'Pending',
  running: 'In progress',
  done: 'Done',
  skipped: 'Skipped',
  failed: 'Failed',
  awaiting_approval: 'Awaiting approval',
};

const GoalStatusIcon = ({ status, label }: { status: GoalStatus; label: string }) => {
  const props = { fontSize: 'small' as const, titleAccess: label };
  switch (status) {
    case 'done':
      return <CheckCircleOutlined {...props} color="success" />;
    case 'running':
      return <Spinner size="sm" label={label} />;
    case 'failed':
      return <ErrorOutline {...props} color="error" />;
    case 'skipped':
      return <RemoveCircleOutline {...props} color="disabled" />;
    case 'awaiting_approval':
      return <PanToolOutlined {...props} color="warning" />;
    default:
      return <RadioButtonUncheckedOutlined {...props} color="disabled" />;
  }
};

const GoalList = ({ goals, depth }: { goals: GoalPlanItem[]; depth: number }) => {
  const { t_i18n } = useFormatter();
  return (
    <Box component="ol" sx={{ listStyle: 'none', margin: 0, paddingLeft: depth === 0 ? 0 : 3 }}>
      {goals.map((goal, index) => {
        const statusLabel = t_i18n(GOAL_STATUS_LABELS[goal.status]);
        return (
          <Box component="li" key={goal.id} sx={{ paddingY: 0.75 }} data-testid="investigation-goal">
            <Stack direction="row" spacing={1.5} alignItems="flex-start">
              <Box sx={{ paddingTop: '2px', display: 'inline-flex' }}><GoalStatusIcon status={goal.status} label={statusLabel} /></Box>
              <Stack spacing={0.5} sx={{ flex: 1 }}>
                <Typography variant="body2" sx={{ color: goal.status === 'skipped' ? 'text.secondary' : 'text.primary' }}>
                  {depth === 0 ? `${index + 1}. ` : ''}
                  {goal.title}
                </Typography>
                {(goal.kind || goal.approvalRequired) && (
                  <Stack direction="row" spacing={1}>
                    {goal.kind && <Chip label={t_i18n(PLAN_STEP_KIND_LABELS[goal.kind] ?? goal.kind)} size="sm" />}
                    {goal.approvalRequired && <Chip label={t_i18n('Needs approval')} severity="medium" size="sm" />}
                  </Stack>
                )}
              </Stack>
            </Stack>
            {goal.children.length > 0 && <GoalList goals={goal.children} depth={depth + 1} />}
          </Box>
        );
      })}
    </Box>
  );
};

interface InvestigationRunGoalPlanProps {
  plan: InvestigationRunView_run$data['plan'];
  goalPlan: unknown;
  runStatus: string;
}

/** The goal plan of the investigation: the engine's own when it sent one, else the run's plan. */
const InvestigationRunGoalPlan = ({ plan, goalPlan, runStatus }: InvestigationRunGoalPlanProps) => {
  const { t_i18n } = useFormatter();
  const goals = goalsFromGoalPlan(goalPlan) ?? goalsFromPlan(plan);
  const done = goals.filter((goal) => goal.status === 'done').length;
  return (
    <Card title={goals.length > 0 ? `${t_i18n('Goal plan')} (${done}/${goals.length})` : t_i18n('Goal plan')}>
      {goals.length > 0
        ? <GoalList goals={goals} depth={0} />
        : (
            <Typography variant="body2" color="text.secondary">
              {isRunActive(runStatus) ? t_i18n('The goal plan is being prepared.') : t_i18n('No goal plan was produced.')}
            </Typography>
          )}
    </Card>
  );
};

export default InvestigationRunGoalPlan;
