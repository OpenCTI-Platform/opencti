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

import React, { Suspense, useEffect, useState } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { useNavigate } from 'react-router';
import { Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import Button from '@common/button/Button';
import { useFormatter } from '../../../components/i18n';
import useEnterpriseEdition from '../../../utils/hooks/useEnterpriseEdition';
import InvestigationRunDrawer from './InvestigationRunDrawer';
import InvestigationRunStatusChip from './InvestigationRunStatusChip';
import { caseAutopilotPath, INVESTIGATION_LAUNCHED$, runStatusLabel } from './investigationRunUtils';
import { LatestInvestigationChipQuery } from './__generated__/LatestInvestigationChipQuery.graphql';

const latestInvestigationChipQuery = graphql`
  query LatestInvestigationChipQuery($subjectId: String!) {
    investigationRuns(subjectId: $subjectId, first: 1, orderBy: created_at, orderMode: desc) {
      edges {
        node {
          id
          run_status
          created_at
          policy {
            id
            name
          }
          case {
            id
            entity_type
          }
        }
      }
    }
  }
`;

interface LatestInvestigationChipProps {
  subjectId: string;
}

const LatestInvestigationLink = ({ subjectId, fetchKey }: LatestInvestigationChipProps & { fetchKey: number }) => {
  const { t_i18n, rd, fldt } = useFormatter();
  const navigate = useNavigate();
  const [drawerRunId, setDrawerRunId] = useState<string | null>(null);
  const data = useLazyLoadQuery<LatestInvestigationChipQuery>(latestInvestigationChipQuery, { subjectId }, { fetchPolicy: 'store-and-network', fetchKey });
  const run = data.investigationRuns?.edges?.[0]?.node;
  if (!run) return null;
  const { case: caseRef } = run;
  // The results live in the Autopilot tab of the case; a case still in the
  // investigation draft is not visible yet, so the run opens in place.
  const open = () => (caseRef ? navigate(caseAutopilotPath(caseRef, run.id)) : setDrawerRunId(run.id));
  const started = run.policy?.name
    ? t_i18n('Started {time} - {policy}', { values: { time: rd(run.created_at), policy: run.policy.name } })
    : t_i18n('Started {time}', { values: { time: rd(run.created_at) } });
  return (
    <>
      <Tooltip>
        <TooltipTrigger asChild>
          <Button
            variant="tertiary"
            size="small"
            onClick={open}
            endIcon={<InvestigationRunStatusChip status={run.run_status} size="sm" />}
            aria-label={`${t_i18n('Latest investigation')}: ${t_i18n(runStatusLabel(run.run_status))}`}
            data-testid="latest-investigation"
          >
            {t_i18n('Latest investigation')}
          </Button>
        </TooltipTrigger>
        <TooltipContent>{`${started} (${fldt(run.created_at)})`}</TooltipContent>
      </Tooltip>
      <InvestigationRunDrawer
        runId={drawerRunId}
        currentEntityId={subjectId}
        onClose={() => setDrawerRunId(null)}
        onRunStarted={(runId) => {
          setDrawerRunId(runId);
          INVESTIGATION_LAUNCHED$.next(subjectId);
        }}
      />
    </>
  );
};

/** The compact "Latest investigation" link of an indicator or an observable overview. */
const LatestInvestigationChip = ({ subjectId }: LatestInvestigationChipProps) => {
  const isEnterpriseEdition = useEnterpriseEdition();
  const [fetchKey, setFetchKey] = useState(0);
  // A launch from the Ask AI menu of this overview makes its run the latest one.
  useEffect(() => {
    const subscription = INVESTIGATION_LAUNCHED$.subscribe((launchedOn) => {
      if (launchedOn === subjectId) setFetchKey((key) => key + 1);
    });
    return () => subscription.unsubscribe();
  }, [subjectId]);
  if (!isEnterpriseEdition) return null;
  return (
    <Suspense fallback={null}>
      <LatestInvestigationLink subjectId={subjectId} fetchKey={fetchKey} />
    </Suspense>
  );
};

export default LatestInvestigationChip;
