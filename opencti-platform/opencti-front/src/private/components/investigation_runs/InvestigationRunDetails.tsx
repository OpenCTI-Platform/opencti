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

import React, { Suspense } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { Link } from 'react-router';
import Box from '@mui/material/Box';
import Stack from '@mui/material/Stack';
import Typography from '@mui/material/Typography';
import { Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import Card from '@common/card/Card';
import ItemIcon from '../../../components/ItemIcon';
import { useFormatter } from '../../../components/i18n';
import useGranted, { SETTINGS_SETCUSTOMIZATION } from '../../../utils/hooks/useGranted';
import { DEFAULT_PACK, elementPath, formatProbability, isRunActive } from './investigationRunUtils';
import { elapsedMs, formatDuration, POLICIES_PATH } from './investigationRunOutcomes';
import type { InvestigationRunView_run$data } from './__generated__/InvestigationRunView_run.graphql';
import { InvestigationRunDetailsPacksQuery } from './__generated__/InvestigationRunDetailsPacksQuery.graphql';

type Run = InvestigationRunView_run$data;

const investigationRunDetailsPacksQuery = graphql`
  query InvestigationRunDetailsPacksQuery {
    investigationPacks {
      packs {
        slug
        label
      }
    }
  }
`;

const CustomPack = ({ slug }: { slug: string }) => {
  const { t_i18n } = useFormatter();
  return (
    <Tooltip>
      <TooltipTrigger asChild><span tabIndex={0}>{t_i18n('Custom pack')}</span></TooltipTrigger>
      <TooltipContent>{slug}</TooltipContent>
    </Tooltip>
  );
};

const BuiltPackName = ({ slug }: { slug: string }) => {
  const data = useLazyLoadQuery<InvestigationRunDetailsPacksQuery>(investigationRunDetailsPacksQuery, {}, { fetchPolicy: 'store-or-network' });
  const pack = data.investigationPacks?.packs.find((item) => item.slug === slug);
  return pack ? <>{pack.label}</> : <CustomPack slug={slug} />;
};

const PackName = ({ slug }: { slug: string | null | undefined }) => {
  const { t_i18n } = useFormatter();
  if (!slug || slug === DEFAULT_PACK) return <>{t_i18n('OpenCTI case investigation')}</>;
  return <Suspense fallback={<CustomPack slug={slug} />}><BuiltPackName slug={slug} /></Suspense>;
};

const Row = ({ label, children }: { label: string; children: React.ReactNode }) => (
  <Stack spacing={0.25} sx={{ minWidth: 0 }}>
    <Typography variant="caption" color="text.secondary">{label}</Typography>
    <Box sx={{ typography: 'body2', minWidth: 0, overflowWrap: 'anywhere' }}>{children}</Box>
  </Stack>
);

const EntityLink = ({ entity, current }: { entity: { id: string; entity_type: string; name: string }; current: boolean }) => (
  <Stack direction="row" spacing={0.75} alignItems="center" sx={{ minWidth: 0 }}>
    <ItemIcon type={entity.entity_type} size="small" />
    {current ? <span>{entity.name}</span> : <Link to={elementPath(entity.id)}>{entity.name}</Link>}
  </Stack>
);

interface InvestigationRunDetailsProps {
  run: Run;
  currentEntityId?: string;
}

/** The facts of an investigation, without placeholders: what it investigates, under which policy and pack, as whom, for how long. */
const InvestigationRunDetails = ({ run, currentEntityId }: InvestigationRunDetailsProps) => {
  const { t_i18n, rd, fldt } = useFormatter();
  const canCustomize = useGranted([SETTINGS_SETCUSTOMIZATION]);
  const active = isRunActive(run.run_status);
  const sameCase = !!run.case && run.subject?.id === run.case.id;
  const subjectName = run.subject?.representative.main;
  const duration = elapsedMs(run.started_at, run.completed_at);
  const acceptance = run.acceptance;
  const decisions = acceptance.hypotheses_accepted + acceptance.hypotheses_rejected + acceptance.recommendations_accepted + acceptance.recommendations_rejected;
  let durationText = t_i18n('Not started yet');
  if (duration !== null) {
    durationText = active
      ? t_i18n('Running for {duration}', { values: { duration: formatDuration(duration, t_i18n) } })
      : t_i18n('Took {duration}', { values: { duration: formatDuration(duration, t_i18n) } });
  }
  return (
    <Card title={t_i18n('Details')}>
      <Box
        sx={{ display: 'grid', gap: 2, gridTemplateColumns: { xs: '1fr', sm: 'repeat(2, minmax(0, 1fr))' } }}
        data-testid="investigation-run-metadata"
      >
        <Row label={t_i18n('Case')}>
          {run.case
            ? <EntityLink entity={run.case} current={run.case.id === currentEntityId} />
            : t_i18n('A new case, in the investigation draft')}
        </Row>
        {!sameCase && (
          <Row label={t_i18n('Investigated entity')}>
            {run.subject && subjectName
              ? <EntityLink entity={{ id: run.subject.id, entity_type: run.subject.entity_type, name: subjectName }} current={run.subject.id === currentEntityId} />
              : t_i18n('Restricted entity')}
          </Row>
        )}
        <Row label={t_i18n('Investigation policy')}>
          {run.policy
            ? (canCustomize ? <Link to={POLICIES_PATH}>{run.policy.name}</Link> : run.policy.name)
            : t_i18n('Not recorded')}
        </Row>
        <Row label={t_i18n('Pack')}><PackName slug={run.pack_id} /></Row>
        <Row label={t_i18n('Run as')}>{run.runAs?.name ?? t_i18n('Not recorded')}</Row>
        <Row label={t_i18n('Started')}>
          {run.started_at ? (
            <Tooltip>
              <TooltipTrigger asChild><span tabIndex={0}>{rd(run.started_at)}</span></TooltipTrigger>
              <TooltipContent>{fldt(run.started_at)}</TooltipContent>
            </Tooltip>
          ) : t_i18n('Not started yet')}
        </Row>
        <Row label={t_i18n('Duration')}>{durationText}</Row>
        {decisions > 0 && acceptance.rate !== null && acceptance.rate !== undefined && (
          <Row label={t_i18n('Analyst acceptance')}>
            {t_i18n('{rate} of {count, plural, one {# decision} other {# decisions}}', { values: { rate: formatProbability(acceptance.rate), count: decisions } })}
          </Row>
        )}
      </Box>
    </Card>
  );
};

export default InvestigationRunDetails;
