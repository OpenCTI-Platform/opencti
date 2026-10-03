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
import { useSearchParams } from 'react-router';
import Stack from '@mui/material/Stack';
import Typography from '@mui/material/Typography';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@filigran/design-system';
import Card from '@common/card/Card';
import { useFormatter } from '../../../components/i18n';
import Loader, { LoaderVariant } from '../../../components/Loader';
import InvestigationRunView from './InvestigationRunView';
import { runStatusLabel } from './investigationRunUtils';
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
  const { t_i18n, fldt } = useFormatter();
  const [searchParams, setSearchParams] = useSearchParams();
  const [fetchKey, setFetchKey] = useState(0);
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
    { fetchPolicy: 'store-and-network', fetchKey: `${requestedRunId ?? ''}-${fetchKey}` },
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
  const requestedMissing = !!requestedRunId && !requestedRun;
  return (
    <Stack spacing={3} data-testid="case-autopilot-tab">
      {(runs.length > 1 || (requestedMissing && runs.length > 0)) && (
        <Select value={selectedRun?.id} onValueChange={selectRun}>
          <SelectTrigger aria-label={t_i18n('Investigation')} style={{ minWidth: 360, alignSelf: 'flex-start' }}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent aria-label={t_i18n('Investigation')}>
            {runs.map((run) => (
              <SelectItem key={run.id} value={run.id}>
                {`${fldt(run.created_at)} - ${t_i18n(runStatusLabel(run.run_status))}`}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      )}
      {requestedMissing && (
        <Card title={t_i18n('Case Autopilot')}>
          <Typography variant="body2" data-testid="case-autopilot-run-missing">
            {t_i18n('This investigation is no longer available.')}
          </Typography>
        </Card>
      )}
      {!requestedMissing && selectedRun && (
        <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <InvestigationRunView key={selectedRun.id} runId={selectedRun.id} currentEntityId={entityId} onDeleted={onDeleted} />
        </Suspense>
      )}
      {!requestedMissing && !selectedRun && (
        <Card title={t_i18n('Case Autopilot')}>
          <Typography variant="body2" data-testid="case-autopilot-empty">
            {t_i18n('No investigation yet. Choose Run Case Autopilot in the Ask AI menu: Case Autopilot investigates with the XTM One investigation engine and the connectors of this platform, scores the hypotheses, proposes recommendations and writes its results to a draft you approve.')}
          </Typography>
        </Card>
      )}
    </Stack>
  );
};

export default InvestigationRunsTab;
