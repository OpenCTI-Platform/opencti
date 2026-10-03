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
import { Link } from 'react-router';
import Box from '@mui/material/Box';
import Stack from '@mui/material/Stack';
import Typography from '@mui/material/Typography';
import Button from '@common/button/Button';
import { useFormatter } from '../../../components/i18n';
import useGranted, { MODULES, SETTINGS_SETCUSTOMIZATION } from '../../../utils/hooks/useGranted';
import { CASE_AUTOPILOT_DOCS_URL, CONNECTORS_PATH, POLICIES_PATH, type StepNextAction, type StepOutcome } from './investigationRunOutcomes';

export interface StepActionHandlers {
  // Absent while the investigation is still running or for a reader who may not launch one.
  onRunAgain?: () => void;
  onReviewApprovals: () => void;
}

export const NextAction = ({ next, handlers }: { next: StepNextAction; handlers: StepActionHandlers }) => {
  const { t_i18n } = useFormatter();
  const canCustomize = useGranted([SETTINGS_SETCUSTOMIZATION]);
  const canManageConnectors = useGranted([MODULES]);
  const policyLabels: Partial<Record<StepNextAction, string>> = {
    policy_connectors: 'Choose connectors in the policy',
    policy_budget: 'Raise the budget in the policy',
    policy_pack: 'Choose another pack in the policy',
    open_policies: 'Open the investigation policies',
  };
  if (next === 'ask_administrator') {
    return (
      <Typography variant="caption" color="text.secondary">
        {t_i18n('Ask your administrator to connect XTM One with its investigation engine.')}
        {' '}
        <a href={CASE_AUTOPILOT_DOCS_URL} target="_blank" rel="noopener noreferrer">{t_i18n('Read the documentation')}</a>
      </Typography>
    );
  }
  const policyLabel = policyLabels[next];
  if (policyLabel) {
    return canCustomize
      ? <Button size="small" variant="tertiary" component={Link} to={POLICIES_PATH}>{t_i18n(policyLabel)}</Button>
      : <Typography variant="caption" color="text.secondary">{t_i18n('Ask your administrator to review the investigation policy.')}</Typography>;
  }
  if (next === 'run_again') {
    return handlers.onRunAgain
      ? <Button size="small" variant="tertiary" onClick={handlers.onRunAgain}>{t_i18n('Run again')}</Button>
      : null;
  }
  if (next === 'review_approvals') {
    return <Button size="small" variant="tertiary" onClick={handlers.onReviewApprovals}>{t_i18n('Review the approvals')}</Button>;
  }
  if (next === 'connectors_status') {
    return canManageConnectors
      ? <Button size="small" variant="tertiary" component={Link} to={CONNECTORS_PATH}>{t_i18n('Check the connectors')}</Button>
      : <Typography variant="caption" color="text.secondary">{t_i18n('Ask your administrator to check the enrichment connectors.')}</Typography>;
  }
  return <Typography variant="caption" color="text.secondary">{t_i18n('Check this source in XTM One, or ask your administrator.')}</Typography>;
};

interface InvestigationRunStepOutcomeProps {
  outcome: StepOutcome;
  tone: 'secondary' | 'warning' | 'error';
  handlers: StepActionHandlers;
}

/** Why a step ended the way it did, what to do about it, and the engine's own words behind "Show details". */
const InvestigationRunStepOutcome = ({ outcome, tone, handlers }: InvestigationRunStepOutcomeProps) => {
  const { t_i18n } = useFormatter();
  const [showDetails, setShowDetails] = useState(false);
  const color = { secondary: 'text.secondary', warning: 'warning.main', error: 'error.main' }[tone];
  return (
    <Stack spacing={0.5}>
      <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
        <Typography variant="body2" color={color}>{outcome.text}</Typography>
        {outcome.next && <NextAction next={outcome.next} handlers={handlers} />}
        {outcome.details && tone !== 'secondary' && (
          <Button size="small" variant="tertiary" onClick={() => setShowDetails(!showDetails)} aria-expanded={showDetails}>
            {showDetails ? t_i18n('Hide details') : t_i18n('Show details')}
          </Button>
        )}
      </Stack>
      {showDetails && outcome.details && (
        <Box component="code" sx={{ typography: 'caption', color: 'text.secondary', wordBreak: 'break-all' }}>{outcome.details}</Box>
      )}
    </Stack>
  );
};

export default InvestigationRunStepOutcome;
