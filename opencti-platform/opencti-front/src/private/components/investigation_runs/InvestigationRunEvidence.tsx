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
import { citationNumbers, isRunActive } from './investigationRunUtils';
import type { InvestigationRunView_run$data } from './__generated__/InvestigationRunView_run.graphql';

const VISIBLE_EVIDENCE = 25;

interface InvestigationRunEvidenceProps {
  run: InvestigationRunView_run$data;
}

/** Everything the investigation cites, numbered like the citations of the report and the hypotheses. */
const InvestigationRunEvidence = ({ run }: InvestigationRunEvidenceProps) => {
  const { t_i18n } = useFormatter();
  const { evidence } = run;
  const [showAll, setShowAll] = useState(false);
  const numbers = citationNumbers(evidence);
  const ordered = [...evidence].sort((a, b) => (numbers.get(a.id) ?? 0) - (numbers.get(b.id) ?? 0));
  const visible = showAll ? ordered : ordered.slice(0, VISIBLE_EVIDENCE);
  return (
    <Card title={`${t_i18n('Evidence')} (${evidence.length})`}>
      {evidence.length === 0 ? (
        <Typography variant="body2" color="text.secondary">
          {isRunActive(run.run_status) ? t_i18n('Evidence appears as the investigation finds it.') : t_i18n('No evidence was collected.')}
        </Typography>
      ) : (
        <Stack spacing={1}>
          <Box component="ol" sx={{ listStyle: 'none', margin: 0, padding: 0 }} aria-label={t_i18n('Cited evidence')}>
            {visible.map((item) => <InvestigationRunEvidenceItem key={item.id} item={item} number={numbers.get(item.id)} />)}
          </Box>
          {evidence.length > VISIBLE_EVIDENCE && (
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
