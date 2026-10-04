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
import Typography from '@mui/material/Typography';
import { Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { useFormatter } from '../../../components/i18n';
import InvestigationRunStatusChip from './InvestigationRunStatusChip';
import { runStatusSentence } from './investigationRunOutcomes';

export interface InvestigationRunBadgeRun {
  readonly id: string;
  readonly run_status: string;
  readonly run_phase: string;
}

interface InvestigationRunBadgeProps {
  run: InvestigationRunBadgeRun | null | undefined;
}

/** Latest Case Autopilot run of a case or an incident, in list rows. */
const InvestigationRunBadge = ({ run }: InvestigationRunBadgeProps) => {
  const { t_i18n } = useFormatter();
  if (!run) {
    return <Typography component="span" variant="caption" color="text.disabled">{t_i18n('No investigation')}</Typography>;
  }
  // A list row knows the state and the phase only: the sentence of the state, without counts.
  const sentence = runStatusSentence({
    run_status: run.run_status,
    run_phase: run.run_phase,
    pendingDraftChanges: 0,
    pendingRequests: 0,
    currentStep: null,
    stepsFound: 0,
    stepsTotal: 0,
  }, t_i18n);
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span style={{ display: 'inline-flex' }}>
          <InvestigationRunStatusChip status={run.run_status} size="sm" />
        </span>
      </TooltipTrigger>
      <TooltipContent>{sentence}</TooltipContent>
    </Tooltip>
  );
};

export default InvestigationRunBadge;
