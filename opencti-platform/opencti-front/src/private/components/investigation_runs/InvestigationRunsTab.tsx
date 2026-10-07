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
import { Link, useSearchParams } from 'react-router';
import Box from '@mui/material/Box';
import Stack from '@mui/material/Stack';
import Typography from '@mui/material/Typography';
import { AutoAwesomeOutlined } from '@mui/icons-material';
import { Alert, Hero, HeroBody, HeroHeader, Select, SelectContent, SelectItem, SelectTrigger, SelectValue, Thumbnail } from '@filigran/design-system';
import Card from '@common/card/Card';
import Button from '@common/button/Button';
import { useFormatter } from '../../../components/i18n';
import useGranted, { KNOWLEDGE_KNUPDATE, SETTINGS_SETCUSTOMIZATION, SETTINGS_SETPARAMETERS } from '../../../utils/hooks/useGranted';
import { useChatbot } from '../chatbox/ChatbotContext';
import InvestigationRunView from './InvestigationRunView';
import InvestigationRunSkeleton from './InvestigationRunSkeleton';
import RunCaseAutopilotDialog from './RunCaseAutopilotDialog';
import { INVESTIGATION_LAUNCHED$, runStatusLabel } from './investigationRunUtils';
import { CASE_AUTOPILOT_DOCS_URL, POLICIES_PATH, XTM_ONE_SETTINGS_PATH } from './investigationRunOutcomes';
import { InvestigationRunsTabQuery } from './__generated__/InvestigationRunsTabQuery.graphql';

const investigationRunsTabQuery = graphql`
  query InvestigationRunsTabQuery($caseId: String, $subjectId: String, $requestedFilters: FilterGroup, $withRequested: Boolean!) {
    investigationRuns(caseId: $caseId, subjectId: $subjectId, first: 25, orderBy: created_at, orderMode: desc) {
      edges {
        node {
          id
          name
          run_status
          run_trigger
          created_at
        }
      }
    }
    requestedRun: investigationRuns(caseId: $caseId, subjectId: $subjectId, filters: $requestedFilters, first: 1) @include(if: $withRequested) {
      edges {
        node {
          id
          name
          run_status
          run_trigger
          created_at
        }
      }
    }
  }
`;

interface InvestigationRunsTabProps {
  entityId: string;
  entityType: string;
}

/** The Autopilot tab of an incident or a case: its investigations, the latest one open and live. */
const InvestigationRunsTab = ({ entityId, entityType }: InvestigationRunsTabProps) => {
  const { t_i18n, rd } = useFormatter();
  const [searchParams, setSearchParams] = useSearchParams();
  const [fetchKey, setFetchKey] = useState(0);
  const [launching, setLaunching] = useState(false);
  const { xtmOneConfigured } = useChatbot();
  // The launch dialog explains when the policy picked runs enrichments the role cannot run.
  const canLaunch = useGranted([KNOWLEDGE_KNUPDATE]);
  const canCustomize = useGranted([SETTINGS_SETCUSTOMIZATION]);
  const canConfigure = useGranted([SETTINGS_SETPARAMETERS]);
  const requestedRunId = searchParams.get('run');
  // A case holds the runs attached to it; an incident, the runs that investigated it.
  const isIncident = entityType === 'Incident';
  // A linked run is loaded on its own, scoped to this entity, so it is found
  // even beyond the latest page and never replaced by another run.
  const data = useLazyLoadQuery<InvestigationRunsTabQuery>(
    investigationRunsTabQuery,
    {
      ...(isIncident ? { subjectId: entityId } : { caseId: entityId }),
      withRequested: !!requestedRunId,
      requestedFilters: requestedRunId ? { mode: 'and', filters: [{ key: ['ids'], values: [requestedRunId] }], filterGroups: [] } : null,
    },
    // The variables already change with the requested run; the key refreshes after a launch or a deletion.
    { fetchPolicy: 'store-and-network', fetchKey },
  );
  const latestRuns = (data.investigationRuns?.edges ?? []).map((edge) => edge.node);
  const requestedRun = requestedRunId ? (data.requestedRun?.edges ?? []).map((edge) => edge.node).find((run) => run.id === requestedRunId) : undefined;
  const runs = requestedRun && !latestRuns.some((run) => run.id === requestedRun.id) ? [...latestRuns, requestedRun] : latestRuns;
  const selectedRun = requestedRunId ? requestedRun : runs[0];
  const selectRun = (runId: string) => setSearchParams({ run: runId }, { replace: true });
  const onDeleted = () => {
    setSearchParams({}, { replace: true });
    setFetchKey(fetchKey + 1);
  };
  const onRunStarted = (runId: string) => {
    setSearchParams({ run: runId }, { replace: true });
    setFetchKey(fetchKey + 1);
  };
  const requestedMissing = !!requestedRunId && !requestedRun;
  return (
    <Stack spacing={3} data-testid="case-autopilot-tab">
      {(runs.length > 1 || (requestedMissing && runs.length > 0)) && (
        <Box sx={{ alignSelf: 'flex-start', minWidth: (theme) => theme.spacing(45) }}>
          <Select value={selectedRun?.id} onValueChange={selectRun}>
            <SelectTrigger aria-label={t_i18n('Investigation')}>
              <SelectValue />
            </SelectTrigger>
            <SelectContent aria-label={t_i18n('Investigation')}>
              {runs.map((run) => (
                <SelectItem key={run.id} value={run.id}>
                  {t_i18n('{time} - {state}', { values: { time: rd(run.created_at), state: t_i18n(runStatusLabel(run.run_status)) } })}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </Box>
      )}
      {requestedMissing && (
        <Card title={t_i18n('Case Autopilot')}>
          <Typography variant="body2" data-testid="case-autopilot-run-missing">
            {t_i18n('This investigation is no longer available.')}
          </Typography>
        </Card>
      )}
      {!requestedMissing && selectedRun && (
        <Suspense fallback={<InvestigationRunSkeleton />}>
          <InvestigationRunView key={selectedRun.id} runId={selectedRun.id} currentEntityId={entityId} onDeleted={onDeleted} onRunStarted={onRunStarted} />
        </Suspense>
      )}
      {!requestedMissing && !selectedRun && xtmOneConfigured === false && (
        <Alert
          severity="warning"
          title={t_i18n('XTM One is not connected')}
          description={t_i18n('Case Autopilot runs on the XTM One investigation engine. Once XTM One is connected, investigations start from this tab or from the Ask AI menu.')}
          action={canConfigure ? <Button size="small" variant="secondary" component={Link} to={XTM_ONE_SETTINGS_PATH}>{t_i18n('Connect XTM One')}</Button> : undefined}
          data-testid="case-autopilot-empty"
        />
      )}
      {!requestedMissing && !selectedRun && xtmOneConfigured !== false && (
        <Hero data-testid="case-autopilot-empty">
          <HeroHeader
            icon={<Thumbnail><AutoAwesomeOutlined /></Thumbnail>}
            action={canLaunch ? (
              <Button intent="ai" onClick={() => setLaunching(true)} data-testid="case-autopilot-empty-run">{t_i18n('Run Case Autopilot')}</Button>
            ) : undefined}
          >
            {t_i18n('Investigate this case with Case Autopilot')}
          </HeroHeader>
          <HeroBody>
            <Stack spacing={1.5}>
              <Typography variant="body2">
                {t_i18n('Case Autopilot reads the case, checks what OpenCTI knows, enriches through your connectors, weighs the hypotheses and proposes a draft for your approval.')}
              </Typography>
              <Stack direction="row" spacing={2} alignItems="center" flexWrap="wrap" useFlexGap>
                <a href={CASE_AUTOPILOT_DOCS_URL} target="_blank" rel="noopener noreferrer">{t_i18n('Read the documentation')}</a>
                {canCustomize && <Link to={POLICIES_PATH}>{t_i18n('Investigation policies')}</Link>}
              </Stack>
            </Stack>
          </HeroBody>
        </Hero>
      )}
      <RunCaseAutopilotDialog
        open={launching}
        subjectId={entityId}
        subjectType={entityType}
        onClose={() => setLaunching(false)}
        onStarted={({ runId }) => {
          setLaunching(false);
          INVESTIGATION_LAUNCHED$.next(entityId);
          onRunStarted(runId);
        }}
      />
    </Stack>
  );
};

export default InvestigationRunsTab;
