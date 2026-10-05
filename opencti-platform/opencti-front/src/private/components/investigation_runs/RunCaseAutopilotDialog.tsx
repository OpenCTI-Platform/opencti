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

import React, { Suspense, useState } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { Link } from 'react-router';
import Stack from '@mui/material/Stack';
import Typography from '@mui/material/Typography';
import DialogActions from '@mui/material/DialogActions';
import {
  Alert,
  Combobox,
  ComboboxContent,
  ComboboxControls,
  ComboboxField,
  ComboboxInput,
  ComboboxTrigger,
  Radio,
  RadioGroup,
  Select,
  SelectContent,
  SelectItem,
  SelectLabel,
  SelectTrigger,
  SelectValue,
  Switch,
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from '@filigran/design-system';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import { useFormatter } from '../../../components/i18n';
import Loader, { LoaderVariant } from '../../../components/Loader';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import useGranted, { KNOWLEDGE_KNENRICHMENT, SETTINGS_SETPARAMETERS } from '../../../utils/hooks/useGranted';
import { useChatbot } from '../chatbox/ChatbotContext';
import InvestigationRunStatusChip from './InvestigationRunStatusChip';
import { caseAutopilotPath, isCaseCreationRefused, rememberGraphAutoOpen, reportMutationOutcome } from './investigationRunUtils';
import { CASE_AUTOPILOT_DOCS_URL, XTM_ONE_SETTINGS_PATH } from './investigationRunOutcomes';
import { RunCaseAutopilotDialogQuery } from './__generated__/RunCaseAutopilotDialogQuery.graphql';
import { RunCaseAutopilotDialogAddMutation } from './__generated__/RunCaseAutopilotDialogAddMutation.graphql';

// Entities whose investigation shows in their own Autopilot tab; the others
// (indicators, observables) are investigated inside a case.
export const AUTOPILOT_TAB_TYPES = ['Incident', 'Case-Incident', 'Case-Rfi', 'Case-Rft'];

const MAX_CASES = 50;

const runCaseAutopilotDialogQuery = graphql`
  query RunCaseAutopilotDialogQuery($subjectId: String, $withCases: Boolean!, $containingFilters: FilterGroup) {
    investigationPolicies(first: 100, orderBy: name, orderMode: asc) {
      edges {
        node {
          id
          name
          description
          is_default
          allowed_actions
        }
      }
    }
    investigationRuns(subjectId: $subjectId, first: 5, orderBy: created_at, orderMode: desc) {
      edges {
        node {
          id
          run_status
          created_at
          case {
            id
            entity_type
            name
          }
        }
      }
    }
    containingCases: cases(first: 50, filters: $containingFilters, orderBy: modified, orderMode: desc) @include(if: $withCases) {
      edges {
        node {
          id
          entity_type
          name
        }
      }
    }
    recentCases: cases(first: 50, orderBy: modified, orderMode: desc) @include(if: $withCases) {
      edges {
        node {
          id
          entity_type
          name
        }
      }
    }
  }
`;

const runCaseAutopilotDialogAddMutation = graphql`
  mutation RunCaseAutopilotDialogAddMutation($subjectId: ID!, $policyId: ID, $caseId: ID) {
    investigationRunAdd(subjectId: $subjectId, policyId: $policyId, caseId: $caseId) {
      id
      run_status
      case_id
      case {
        id
        entity_type
      }
    }
  }
`;

export interface RunCaseAutopilotStarted {
  runId: string;
  caseRef: { id: string; entity_type: string } | null;
}

interface CaseOption {
  id: string;
  entity_type: string;
  name: string;
}

interface LaunchFormProps {
  subjectId: string;
  subjectType: string;
  onStarted: (started: RunCaseAutopilotStarted) => void;
  onCancel: () => void;
}

const LaunchForm = ({ subjectId, subjectType, onStarted, onCancel }: LaunchFormProps) => {
  const { t_i18n, fldt, rd } = useFormatter();
  const { xtmOneConfigured } = useChatbot();
  const needsCase = !AUTOPILOT_TAB_TYPES.includes(subjectType);
  const data = useLazyLoadQuery<RunCaseAutopilotDialogQuery>(runCaseAutopilotDialogQuery, {
    subjectId,
    withCases: needsCase,
    containingFilters: { mode: 'and', filters: [{ key: ['objects'], values: [subjectId] }], filterGroups: [] },
  }, { fetchPolicy: 'network-only' });
  const policies = (data.investigationPolicies?.edges ?? []).map((edge) => edge.node);
  const runs = (data.investigationRuns?.edges ?? []).map((edge) => edge.node);
  const containing = (data.containingCases?.edges ?? []).flatMap((edge) => (edge?.node ? [edge.node] : []));
  const containingIds = new Set(containing.map((item) => item.id));
  const recent = (data.recentCases?.edges ?? []).flatMap((edge) => (edge?.node ? [edge.node] : []));
  const caseOptions: CaseOption[] = [
    ...containing,
    ...recent.filter((item) => !containingIds.has(item.id)),
  ].slice(0, MAX_CASES).map((item) => ({ id: item.id, entity_type: item.entity_type, name: item.name }));
  const defaultPolicy = policies.find((policy) => policy.is_default) ?? policies[0];
  const [policyId, setPolicyId] = useState<string | undefined>(defaultPolicy?.id);
  const [caseMode, setCaseMode] = useState<'new' | 'existing'>(containing.length > 0 ? 'existing' : 'new');
  const [selectedCase, setSelectedCase] = useState<CaseOption | null>(containing[0] ? caseOptions[0] : null);
  const [openGraph, setOpenGraph] = useState(true);
  const [commit, inFlight] = useApiMutation<RunCaseAutopilotDialogAddMutation>(runCaseAutopilotDialogAddMutation);
  const selectedPolicy = policies.find((policy) => policy.id === policyId);
  const engineMissing = xtmOneConfigured !== true;
  const caseMissing = needsCase && caseMode === 'existing' && !selectedCase;
  const canConfigure = useGranted([SETTINGS_SETPARAMETERS]);
  const canEnrich = useGranted([KNOWLEDGE_KNENRICHMENT]);
  const enrichmentRefused = !canEnrich && !!selectedPolicy?.allowed_actions.includes('enrichment');
  const caseCreationRefused = isCaseCreationRefused(needsCase, caseMode, selectedPolicy?.allowed_actions);
  let startBlocker: string | null = null;
  if (engineMissing) startBlocker = t_i18n('XTM One is not connected');
  else if (enrichmentRefused) startBlocker = t_i18n('This policy runs enrichments, which your role does not allow: choose another policy');
  else if (caseCreationRefused) startBlocker = t_i18n('This policy does not create cases: select an existing case or choose another policy');
  else if (caseMissing) startBlocker = t_i18n('Select the case of the investigation');
  let intro = t_i18n('Investigates this observable with XTM One and drafts the findings for your approval.');
  if (subjectType === 'Indicator') intro = t_i18n('Investigates this indicator with XTM One and drafts the findings for your approval.');
  else if (subjectType === 'Incident') intro = t_i18n('Investigates this incident with XTM One and drafts the findings for your approval.');
  else if (!needsCase) intro = t_i18n('Investigates this case with XTM One and drafts the findings for your approval.');
  const start = () => {
    commit({
      variables: {
        subjectId,
        policyId: policyId ?? null,
        caseId: needsCase && caseMode === 'existing' ? selectedCase?.id ?? null : null,
      },
      onCompleted: (response, errors) => {
        const run = response.investigationRunAdd;
        // A launch that failed neither navigates nor says it started.
        if (!run || !reportMutationOutcome(errors, t_i18n('Case Autopilot has started the investigation'))) return;
        if (openGraph) rememberGraphAutoOpen(run.id);
        onStarted({ runId: run.id, caseRef: run.case ? { id: run.case.id, entity_type: run.case.entity_type } : null });
      },
    });
  };
  return (
    <Stack spacing={3} data-testid="run-case-autopilot-form">
      <Typography variant="body2">
        {intro}
        {' '}
        <a href={CASE_AUTOPILOT_DOCS_URL} target="_blank" rel="noopener noreferrer">{t_i18n('Learn more')}</a>
      </Typography>
      {engineMissing && (
        <Alert
          severity="warning"
          title={t_i18n('XTM One is not connected')}
          description={t_i18n('Case Autopilot runs on the XTM One investigation engine.')}
          action={canConfigure ? <Button size="small" variant="secondary" component={Link} to={XTM_ONE_SETTINGS_PATH}>{t_i18n('Connect XTM One')}</Button> : undefined}
          data-testid="run-case-autopilot-no-engine"
        />
      )}
      <Select value={policyId} onValueChange={setPolicyId}>
        <SelectLabel>{t_i18n('Investigation policy')}</SelectLabel>
        <SelectTrigger aria-label={t_i18n('Investigation policy')}>
          <SelectValue placeholder={t_i18n('Default investigation policy')} />
        </SelectTrigger>
        <SelectContent aria-label={t_i18n('Investigation policy')}>
          {policies.map((policy) => (
            <SelectItem key={policy.id} value={policy.id}>
              {policy.is_default ? t_i18n('{name} (default)', { values: { name: policy.name } }) : policy.name}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      {selectedPolicy?.description && <Typography variant="body2" color="text.secondary">{selectedPolicy.description}</Typography>}
      {enrichmentRefused && (
        <Alert
          severity="warning"
          title={t_i18n('This policy runs enrichments')}
          description={t_i18n('Your role does not allow enriching knowledge: choose a policy without enrichment, or ask your administrator.')}
          data-testid="run-case-autopilot-enrichment-refused"
        />
      )}
      {needsCase && (
        <Stack spacing={1.5}>
          <Typography variant="h4">{t_i18n('Case of the investigation')}</Typography>
          <Typography variant="body2" color="text.secondary">
            {t_i18n('The results of the investigation live in the Autopilot tab of a case.')}
          </Typography>
          <RadioGroup value={caseMode} onValueChange={(value) => setCaseMode(value as 'new' | 'existing')} aria-label={t_i18n('Case of the investigation')}>
            <Radio value="new" label={t_i18n('Create a new incident response case in the investigation draft')} />
            <Radio value="existing" label={t_i18n('Investigate in an existing case')} disabled={caseOptions.length === 0} />
          </RadioGroup>
          {caseCreationRefused && (
            <Alert
              severity="warning"
              title={t_i18n('This policy does not create cases')}
              description={t_i18n('Investigate in an existing case, or choose a policy that allows creating a case.')}
              data-testid="run-case-autopilot-case-creation-refused"
            />
          )}
          {caseMode === 'existing' && (
            <Combobox<CaseOption>
              labelPosition="none"
              clearable={false}
              options={caseOptions}
              getOptionLabel={(option) => option?.name ?? ''}
              value={selectedCase}
              onValueChange={(next) => setSelectedCase((next as CaseOption | null) ?? null)}
            >
              <ComboboxField>
                <ComboboxInput aria-label={t_i18n('Case')} placeholder={t_i18n('Select a case')} />
                <ComboboxControls>
                  <ComboboxTrigger />
                </ComboboxControls>
              </ComboboxField>
              <ComboboxContent emptyMessage={t_i18n('No case found')} listAriaLabel={t_i18n('Case')} />
            </Combobox>
          )}
        </Stack>
      )}
      <Switch
        checked={openGraph}
        onCheckedChange={setOpenGraph}
        label={t_i18n('Open the investigation graph when the investigation completes')}
      />
      {runs.length > 0 && (
        <Stack spacing={1}>
          <Typography variant="h4">{t_i18n('Previous investigations')}</Typography>
          {runs.map((run) => (
            <Stack key={run.id} direction="row" spacing={2} alignItems="center" data-testid="run-case-autopilot-previous">
              <InvestigationRunStatusChip status={run.run_status} size="sm" />
              <Tooltip>
                <TooltipTrigger asChild>
                  <Typography variant="body2" tabIndex={0}>{rd(run.created_at)}</Typography>
                </TooltipTrigger>
                <TooltipContent>{fldt(run.created_at)}</TooltipContent>
              </Tooltip>
              {run.case && <Link to={caseAutopilotPath(run.case, run.id)} onClick={onCancel}>{run.case.name}</Link>}
            </Stack>
          ))}
        </Stack>
      )}
      <DialogActions>
        <Button variant="secondary" onClick={onCancel} disabled={inFlight}>{t_i18n('Cancel')}</Button>
        {startBlocker ? (
          <Tooltip>
            <TooltipTrigger asChild>
              <span tabIndex={0}>
                <Button intent="ai" disabled data-testid="run-case-autopilot-start">{t_i18n('Run Case Autopilot')}</Button>
              </span>
            </TooltipTrigger>
            <TooltipContent>{startBlocker}</TooltipContent>
          </Tooltip>
        ) : (
          <Button intent="ai" onClick={start} disabled={inFlight} data-testid="run-case-autopilot-start">
            {t_i18n('Run Case Autopilot')}
          </Button>
        )}
      </DialogActions>
    </Stack>
  );
};

interface RunCaseAutopilotDialogProps {
  open: boolean;
  subjectId: string;
  subjectType: string;
  onClose: () => void;
  onStarted: (started: RunCaseAutopilotStarted) => void;
}

/** "Run Case Autopilot" from the Ask AI menu: the policy, and the case an indicator or an observable is investigated in. */
const RunCaseAutopilotDialog = ({ open, subjectId, subjectType, onClose, onStarted }: RunCaseAutopilotDialogProps) => {
  const { t_i18n } = useFormatter();
  return (
    <Dialog open={open} onClose={onClose} title={t_i18n('Run Case Autopilot')} size="medium">
      {open ? (
        <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <LaunchForm subjectId={subjectId} subjectType={subjectType} onStarted={onStarted} onCancel={onClose} />
        </Suspense>
      ) : <span />}
    </Dialog>
  );
};

export default RunCaseAutopilotDialog;
