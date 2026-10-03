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
import { useNavigate } from 'react-router';
import Stack from '@mui/material/Stack';
import Typography from '@mui/material/Typography';
import DialogActions from '@mui/material/DialogActions';
import { LogoXtmOneIcon } from 'filigran-icon';
import { Select, SelectContent, SelectItem, SelectLabel, SelectTrigger, SelectValue, Switch } from '@filigran/design-system';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import FiligranIcon from '@components/common/FiligranIcon';
import EEChip from '@components/common/entreprise_edition/EEChip';
import EnterpriseEditionAgreement from '@components/common/entreprise_edition/EnterpriseEditionAgreement';
import FeedbackCreation from '@components/cases/feedbacks/FeedbackCreation';
import { useFormatter } from '../../../components/i18n';
import Loader, { LoaderVariant } from '../../../components/Loader';
import Security from '../../../utils/Security';
import useAuth from '../../../utils/hooks/useAuth';
import useDraftContext from '../../../utils/hooks/useDraftContext';
import useEnterpriseEdition from '../../../utils/hooks/useEnterpriseEdition';
import useGranted, { KNOWLEDGE_KNENRICHMENT, KNOWLEDGE_KNUPDATE, SETTINGS_SETPARAMETERS } from '../../../utils/hooks/useGranted';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import { useChatbot } from '../chatbox/ChatbotContext';
import InvestigationRunDrawer from './InvestigationRunDrawer';
import InvestigationRunStatusChip from './InvestigationRunStatusChip';
import { rememberGraphAutoOpen } from './investigationRunUtils';
import { InvestigateWithAIQuery } from './__generated__/InvestigateWithAIQuery.graphql';
import { InvestigateWithAIAddMutation } from './__generated__/InvestigateWithAIAddMutation.graphql';

const investigateWithAIQuery = graphql`
  query InvestigateWithAIQuery($subjectId: String) {
    investigationPolicies(first: 100, orderBy: name, orderMode: asc) {
      edges {
        node {
          id
          name
          description
          is_default
        }
      }
    }
    investigationRuns(subjectId: $subjectId, first: 5, orderBy: created_at, orderMode: desc) {
      edges {
        node {
          id
          run_status
          created_at
        }
      }
    }
  }
`;

const investigateWithAIAddMutation = graphql`
  mutation InvestigateWithAIAddMutation($subjectId: ID!, $policyId: ID) {
    investigationRunAdd(subjectId: $subjectId, policyId: $policyId) {
      id
      run_status
    }
  }
`;

interface LaunchFormProps {
  subjectId: string;
  onStarted: (runId: string) => void;
  onOpenRun: (runId: string) => void;
  onCancel: () => void;
}

const LaunchForm = ({ subjectId, onStarted, onOpenRun, onCancel }: LaunchFormProps) => {
  const { t_i18n, fldt } = useFormatter();
  const { xtmOneConfigured } = useChatbot();
  const data = useLazyLoadQuery<InvestigateWithAIQuery>(investigateWithAIQuery, { subjectId }, { fetchPolicy: 'network-only' });
  const policies = (data.investigationPolicies?.edges ?? []).map((edge) => edge.node);
  const runs = (data.investigationRuns?.edges ?? []).map((edge) => edge.node);
  const defaultPolicy = policies.find((policy) => policy.is_default) ?? policies[0];
  const [policyId, setPolicyId] = useState<string | undefined>(defaultPolicy?.id);
  const [openGraph, setOpenGraph] = useState(true);
  const [commit, inFlight] = useApiMutation<InvestigateWithAIAddMutation>(investigateWithAIAddMutation, undefined, {
    successMessage: t_i18n('The investigation has started'),
  });
  const selectedPolicy = policies.find((policy) => policy.id === policyId);
  const start = () => {
    commit({
      variables: { subjectId, policyId: policyId ?? null },
      onCompleted: (response) => {
        const runId = response.investigationRunAdd?.id;
        if (!runId) return;
        if (openGraph) rememberGraphAutoOpen(runId);
        onStarted(runId);
      },
    });
  };
  return (
    <Stack spacing={3}>
      <Typography variant="body2">
        {t_i18n('Case Autopilot runs a complete investigation of this entity: enrichment through the connectors of this platform, pivots in the knowledge graph, attribution hypotheses scored by OpenCTI, recommendations and a draft report. Everything it writes goes to a draft you approve.')}
      </Typography>
      {xtmOneConfigured !== true && (
        <Typography variant="body2" color="warning.main" data-testid="investigate-with-ai-no-agent">
          {t_i18n('XTM One is not connected: the investigation collects the context, runs the enrichments and rebuilds the timeline, without attribution hypotheses or recommendations.')}
        </Typography>
      )}
      <Select value={policyId} onValueChange={setPolicyId}>
        <SelectLabel>{t_i18n('Investigation policy')}</SelectLabel>
        <SelectTrigger aria-label={t_i18n('Investigation policy')}>
          <SelectValue placeholder={t_i18n('Default policy')} />
        </SelectTrigger>
        <SelectContent>
          {policies.map((policy) => (
            <SelectItem key={policy.id} value={policy.id}>
              {policy.is_default ? `${policy.name} (${t_i18n('default')})` : policy.name}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      {selectedPolicy?.description && <Typography variant="body2" color="text.secondary">{selectedPolicy.description}</Typography>}
      <Switch
        checked={openGraph}
        onCheckedChange={setOpenGraph}
        label={t_i18n('Open the investigation graph when the investigation completes')}
      />
      {runs.length > 0 && (
        <Stack spacing={1}>
          <Typography variant="h4">{t_i18n('Previous investigations')}</Typography>
          {runs.map((run) => (
            <Stack key={run.id} direction="row" spacing={2} alignItems="center" justifyContent="space-between">
              <Stack direction="row" spacing={1} alignItems="center">
                <InvestigationRunStatusChip status={run.run_status} size="sm" />
                <Typography variant="body2">{fldt(run.created_at)}</Typography>
              </Stack>
              <Button size="small" variant="tertiary" onClick={() => onOpenRun(run.id)}>{t_i18n('View')}</Button>
            </Stack>
          ))}
        </Stack>
      )}
      <DialogActions>
        <Button variant="secondary" onClick={onCancel} disabled={inFlight}>{t_i18n('Cancel')}</Button>
        <Button intent="ai" variant="secondary" onClick={start} disabled={inFlight} data-testid="investigate-with-ai-start">
          {t_i18n('Start the investigation')}
        </Button>
      </DialogActions>
    </Stack>
  );
};

interface InvestigateWithAIProps {
  subjectId: string;
  /** Path of the case page: cases show the investigation in their Autopilot tab, other entities in a drawer. */
  caseBasePath?: string;
}

/** "Investigate with AI" on the overview of an incident, a case, an indicator or an observable. */
const InvestigateWithAI = ({ subjectId, caseBasePath }: InvestigateWithAIProps) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const isEnterpriseEdition = useEnterpriseEdition();
  const isAdmin = useGranted([SETTINGS_SETPARAMETERS]);
  const draftContext = useDraftContext();
  const { settings: { id: settingsId } } = useAuth();
  const [launching, setLaunching] = useState(false);
  const [eeDialog, setEeDialog] = useState(false);
  const [drawerRunId, setDrawerRunId] = useState<string | null>(null);
  // Investigations act on the live graph and write to their own draft.
  if (draftContext) return null;
  const openRun = (runId: string) => {
    setLaunching(false);
    if (caseBasePath) {
      navigate(`${caseBasePath}/autopilot?run=${runId}`);
    } else {
      setDrawerRunId(runId);
    }
  };
  const button = (onClick: () => void, showEEChip = false) => (
    <Button
      variant="tertiary"
      size="small"
      intent="ai"
      onClick={onClick}
      startIcon={<FiligranIcon icon={LogoXtmOneIcon} size={16} />}
      data-testid="investigate-with-ai"
    >
      {t_i18n('Investigate with AI')}
      {showEEChip && <EEChip feature="Case Autopilot" size="sm" />}
    </Button>
  );
  if (!isEnterpriseEdition) {
    return (
      <>
        {button(() => setEeDialog(true), true)}
        {isAdmin ? (
          <EnterpriseEditionAgreement open={eeDialog} onClose={() => setEeDialog(false)} settingsId={settingsId} />
        ) : (
          <FeedbackCreation
            openDrawer={eeDialog}
            handleCloseDrawer={() => setEeDialog(false)}
            initialValue={{ description: t_i18n('I would like to use the Enterprise Edition feature Case Autopilot but the Enterprise Edition is not activated.') }}
          />
        )}
      </>
    );
  }
  return (
    <Security needs={[KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNENRICHMENT]} matchAll>
      <>
        {button(() => setLaunching(true))}
        <Dialog open={launching} onClose={() => setLaunching(false)} title={t_i18n('Investigate with AI')} size="medium">
          {launching ? (
            <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
              <LaunchForm subjectId={subjectId} onStarted={openRun} onOpenRun={openRun} onCancel={() => setLaunching(false)} />
            </Suspense>
          ) : <span />}
        </Dialog>
        {!caseBasePath && <InvestigationRunDrawer runId={drawerRunId} currentEntityId={subjectId} onClose={() => setDrawerRunId(null)} />}
      </>
    </Security>
  );
};

export default InvestigateWithAI;
