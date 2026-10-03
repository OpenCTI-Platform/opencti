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
import { Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { useFormatter } from '../../../components/i18n';
import InvestigationRunStatusChip from './InvestigationRunStatusChip';
import { runPhaseLabel } from './investigationRunUtils';

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
    return <span aria-label={t_i18n('No investigation')}>-</span>;
  }
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span style={{ display: 'inline-flex' }}>
          <InvestigationRunStatusChip status={run.run_status} size="sm" />
        </span>
      </TooltipTrigger>
      <TooltipContent>{`${t_i18n('Case Autopilot')}: ${t_i18n(runPhaseLabel(run.run_phase))}`}</TooltipContent>
    </Tooltip>
  );
};

export default InvestigationRunBadge;
