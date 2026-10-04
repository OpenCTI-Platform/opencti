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
import Box from '@mui/material/Box';
import Stack from '@mui/material/Stack';
import Typography from '@mui/material/Typography';
import Card from '@common/card/Card';
import Button from '@common/button/Button';
import { useFormatter } from '../../../components/i18n';
import InvestigationRunEvidenceItem from './InvestigationRunEvidenceItem';
import { citationNumbers, emptySectionSentence, isEarlierEvidence } from './investigationRunUtils';
import type { InvestigationRunView_run$data } from './__generated__/InvestigationRunView_run.graphql';

const VISIBLE_EVIDENCE = 25;

interface InvestigationRunEvidenceProps {
  run: InvestigationRunView_run$data;
}

/**
 * Everything the investigation cites, numbered like the citations of the
 * report and the hypotheses. After a continuation, what earlier engine runs
 * found is listed apart, unnumbered: each engine run cites from 1.
 */
const InvestigationRunEvidence = ({ run }: InvestigationRunEvidenceProps) => {
  const { t_i18n } = useFormatter();
  const { evidence } = run;
  const [showAll, setShowAll] = useState(false);
  const latest = run.xtm_investigation_id;
  const numbers = citationNumbers(evidence, latest);
  const current = evidence.filter((item) => !isEarlierEvidence(item, latest))
    .sort((a, b) => (numbers.get(a.id) ?? 0) - (numbers.get(b.id) ?? 0));
  const earlier = evidence.filter((item) => isEarlierEvidence(item, latest));
  const visible = showAll ? current : current.slice(0, VISIBLE_EVIDENCE);
  const visibleEarlier = showAll ? earlier : earlier.slice(0, Math.max(0, VISIBLE_EVIDENCE - visible.length));
  const hidden = current.length + earlier.length - visible.length - visibleEarlier.length;
  return (
    <Card
      title={t_i18n('Evidence')}
      action={evidence.length > 0 ? (
        <Typography variant="body2" color="text.secondary" data-testid="investigation-evidence-count">
          {t_i18n('{count, plural, one {# evidence item} other {# evidence items}}', { values: { count: evidence.length } })}
        </Typography>
      ) : undefined}
    >
      {evidence.length === 0 ? (
        <Typography variant="body2" color="text.secondary">
          {emptySectionSentence(run, t_i18n, t_i18n('Evidence appears as the investigation finds it.'), t_i18n('No evidence was collected.'))}
        </Typography>
      ) : (
        <Stack spacing={1}>
          {visible.length > 0 && (
            <Box component="ol" sx={{ listStyle: 'none', margin: 0, padding: 0 }} aria-label={t_i18n('Cited evidence')}>
              {visible.map((item) => <InvestigationRunEvidenceItem key={item.id} item={item} number={numbers.get(item.id)} />)}
            </Box>
          )}
          {visibleEarlier.length > 0 && (
            <Stack spacing={0.5} data-testid="investigation-evidence-earlier">
              <Typography variant="subtitle2" color="text.secondary" component="h4">
                {t_i18n('Found by earlier investigations of this run')}
              </Typography>
              <Box component="ul" sx={{ listStyle: 'none', margin: 0, padding: 0 }} aria-label={t_i18n('Found by earlier investigations of this run')}>
                {visibleEarlier.map((item) => <InvestigationRunEvidenceItem key={item.id} item={item} number={undefined} />)}
              </Box>
            </Stack>
          )}
          {(hidden > 0 || showAll) && evidence.length > VISIBLE_EVIDENCE && (
            <Box>
              <Button size="small" variant="tertiary" onClick={() => setShowAll(!showAll)} aria-expanded={showAll}>
                {showAll ? t_i18n('Show less') : t_i18n('Show all {count} evidence items', { values: { count: evidence.length } })}
              </Button>
            </Box>
          )}
        </Stack>
      )}
    </Card>
  );
};

export default InvestigationRunEvidence;
