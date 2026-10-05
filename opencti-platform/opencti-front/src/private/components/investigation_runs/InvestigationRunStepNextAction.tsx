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
import { Alert } from '@filigran/design-system';
import Button from '@common/button/Button';
import { useFormatter } from '../../../components/i18n';
import useGranted, { MODULES, SETTINGS_SETCUSTOMIZATION, SETTINGS_SETPARAMETERS } from '../../../utils/hooks/useGranted';
import { CASE_AUTOPILOT_DOCS_URL, CONNECTORS_PATH, POLICIES_PATH, type StepNextAction, type StepOutcome, XTM_ONE_SETTINGS_PATH } from './investigationRunOutcomes';

export interface StepActionHandlers {
  // Absent while the investigation is still running or for a reader who may not launch one.
  onRunAgain?: () => void;
  // Present only when the investigation can be continued.
  onContinue?: () => void;
  onReviewApprovals: () => void;
  // The observables tab of the case, when the case is live.
  caseObservablesPath?: string | null;
  // The draft of the investigation, read-only once it was validated.
  draftPath?: string | null;
}

const POLICY_LABELS: Partial<Record<StepNextAction, string>> = {
  policy_connectors: 'Choose connectors in the policy',
  policy_budget: 'Raise the budget in the policy',
  policy_pack: 'Choose another pack in the policy',
  open_policies: 'Open the investigation policies',
};

/** One next action of the shared matrix, as a control when the reader can take it, else as guidance. */
export const NextAction = ({ next, handlers }: { next: StepNextAction; handlers: StepActionHandlers }) => {
  const { t_i18n } = useFormatter();
  const canCustomize = useGranted([SETTINGS_SETCUSTOMIZATION]);
  const canManageConnectors = useGranted([MODULES]);
  const canConfigure = useGranted([SETTINGS_SETPARAMETERS]);
  const policyLabel = POLICY_LABELS[next];
  if (policyLabel) {
    return canCustomize
      ? <Button size="small" variant="secondary" component={Link} to={POLICIES_PATH}>{t_i18n(policyLabel)}</Button>
      : <Typography variant="caption" color="text.secondary">{t_i18n('Ask your administrator to review the investigation policy.')}</Typography>;
  }
  switch (next) {
    case 'run_again':
      return handlers.onRunAgain ? <Button size="small" variant="secondary" onClick={handlers.onRunAgain}>{t_i18n('Run again')}</Button> : null;
    case 'run_again_later':
      return <Typography variant="caption" color="text.secondary">{t_i18n('Run again later.')}</Typography>;
    case 'continue':
      return handlers.onContinue ? <Button size="small" variant="secondary" intent="ai" onClick={handlers.onContinue}>{t_i18n('Continue the investigation')}</Button> : null;
    case 'review_approvals':
      return <Button size="small" variant="secondary" onClick={handlers.onReviewApprovals}>{t_i18n('Review')}</Button>;
    case 'add_observables':
      return handlers.caseObservablesPath
        ? <Button size="small" variant="secondary" component={Link} to={handlers.caseObservablesPath}>{t_i18n('Add observables to the case')}</Button>
        : null;
    case 'open_draft':
      return handlers.draftPath
        ? <Button size="small" variant="secondary" component={Link} to={handlers.draftPath} data-testid="investigation-run-open-draft">{t_i18n('Open the draft')}</Button>
        : null;
    case 'connectors_status':
      return canManageConnectors
        ? <Button size="small" variant="secondary" component={Link} to={CONNECTORS_PATH}>{t_i18n('Check the connectors')}</Button>
        : <Typography variant="caption" color="text.secondary">{t_i18n('Ask your administrator to check the enrichment connectors.')}</Typography>;
    case 'ask_administrator':
      return canConfigure
        ? <Button size="small" variant="secondary" component={Link} to={XTM_ONE_SETTINGS_PATH}>{t_i18n('Connect XTM One')}</Button>
        : (
            <Typography variant="caption" color="text.secondary">
              {t_i18n('Ask your administrator to connect XTM One with its investigation engine.')}
              {' '}
              <a href={CASE_AUTOPILOT_DOCS_URL} target="_blank" rel="noopener noreferrer">{t_i18n('Read the documentation')}</a>
            </Typography>
          );
    default:
      return (
        <Typography variant="caption" color="text.secondary">
          {canConfigure ? t_i18n('Check the integration in XTM One.') : t_i18n('Ask your administrator to check this source in XTM One.')}
        </Typography>
      );
  }
};

interface InvestigationRunStepOutcomeProps {
  outcome: StepOutcome;
  tone: 'neutral' | 'warning' | 'error';
  handlers: StepActionHandlers;
}

const Details = ({ details }: { details: string }) => {
  const { t_i18n } = useFormatter();
  const [shown, setShown] = useState(false);
  return (
    <Stack spacing={0.5} alignItems="flex-start">
      <Button size="small" variant="tertiary" onClick={() => setShown(!shown)} aria-expanded={shown}>
        {shown ? t_i18n('Hide details') : t_i18n('Show details')}
      </Button>
      {shown && <Box component="code" sx={{ typography: 'caption', color: 'text.secondary', wordBreak: 'break-all' }}>{details}</Box>}
    </Stack>
  );
};

/**
 * Why a step ended the way it did and what to do about it: an alert for a
 * failure, a partial answer or a step never reached, a plain sentence for a
 * neutral outcome. The engine's own code stays behind "Show details".
 */
const InvestigationRunStepOutcome = ({ outcome, tone, handlers }: InvestigationRunStepOutcomeProps) => {
  const actions = [outcome.next, outcome.also].filter((action): action is StepNextAction => !!action);
  const actionNodes = actions.map((action) => <NextAction key={action} next={action} handlers={handlers} />);
  if (tone === 'neutral') {
    return (
      <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
        <Typography variant="body2" color="text.secondary">{outcome.text}</Typography>
        {actionNodes}
      </Stack>
    );
  }
  return (
    <Alert
      severity={tone}
      title={outcome.text}
      description={outcome.details ? <Details details={outcome.details} /> : undefined}
      action={actionNodes.length > 0 ? <Stack direction="row" spacing={1} alignItems="center">{actionNodes}</Stack> : undefined}
    />
  );
};

export default InvestigationRunStepOutcome;
