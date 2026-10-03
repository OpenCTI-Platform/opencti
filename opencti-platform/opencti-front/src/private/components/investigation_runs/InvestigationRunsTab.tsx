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
import InvestigateWithAI from './InvestigateWithAI';
import InvestigationRunView from './InvestigationRunView';
import { runStatusLabel } from './investigationRunUtils';
import { InvestigationRunsTabQuery } from './__generated__/InvestigationRunsTabQuery.graphql';

const investigationRunsTabQuery = graphql`
  query InvestigationRunsTabQuery($caseId: String) {
    investigationRuns(caseId: $caseId, first: 25, orderBy: created_at, orderMode: desc) {
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
  caseId: string;
  caseBasePath: string;
}

/** The Autopilot tab of a case: its investigations, the latest one open and live. */
const InvestigationRunsTab = ({ caseId, caseBasePath }: InvestigationRunsTabProps) => {
  const { t_i18n, fldt } = useFormatter();
  const [searchParams, setSearchParams] = useSearchParams();
  const [fetchKey, setFetchKey] = useState(0);
  const requestedRunId = searchParams.get('run');
  const data = useLazyLoadQuery<InvestigationRunsTabQuery>(
    investigationRunsTabQuery,
    { caseId },
    { fetchPolicy: 'store-and-network', fetchKey: `${requestedRunId ?? ''}-${fetchKey}` },
  );
  const runs = (data.investigationRuns?.edges ?? []).map((edge) => edge.node);
  const selectedRun = runs.find((run) => run.id === requestedRunId) ?? runs[0];
  const selectRun = (runId: string) => setSearchParams({ run: runId }, { replace: true });
  const onDeleted = () => {
    setSearchParams({}, { replace: true });
    setFetchKey(fetchKey + 1);
  };
  return (
    <Stack spacing={3} data-testid="case-autopilot-tab">
      <Stack direction={{ xs: 'column', md: 'row' }} spacing={2} alignItems={{ md: 'center' }} justifyContent="space-between">
        {runs.length > 1 ? (
          <Select value={selectedRun?.id} onValueChange={selectRun}>
            <SelectTrigger aria-label={t_i18n('Investigation')} style={{ minWidth: 360 }}>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {runs.map((run) => (
                <SelectItem key={run.id} value={run.id}>
                  {`${fldt(run.created_at)} - ${t_i18n(runStatusLabel(run.run_status))}`}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        ) : <span />}
        <InvestigateWithAI subjectId={caseId} caseBasePath={caseBasePath} />
      </Stack>
      {selectedRun ? (
        <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <InvestigationRunView key={selectedRun.id} runId={selectedRun.id} currentEntityId={caseId} onDeleted={onDeleted} />
        </Suspense>
      ) : (
        <Card title={t_i18n('Case Autopilot')}>
          <Typography variant="body2">
            {t_i18n('No investigation yet. Case Autopilot investigates this case with the connectors of this platform, scores attribution hypotheses, proposes recommendations and writes its results to a draft you approve.')}
          </Typography>
        </Card>
      )}
    </Stack>
  );
};

export default InvestigationRunsTab;
