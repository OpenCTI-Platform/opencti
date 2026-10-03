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
import { Chip } from '@filigran/design-system';
import Card from '@common/card/Card';
import Button from '@common/button/Button';
import ItemIcon from '../../../components/ItemIcon';
import { useFormatter } from '../../../components/i18n';
import { citationNumbers, elementPath, EVIDENCE_ORIGIN_LABELS } from './investigationRunUtils';
import type { InvestigationRunView_run$data } from './__generated__/InvestigationRunView_run.graphql';

const VISIBLE_EVIDENCE = 25;

interface InvestigationRunEvidenceProps {
  evidence: InvestigationRunView_run$data['evidence'];
}

/** Everything the investigation cites, numbered like the citations of the hypotheses. */
const InvestigationRunEvidence = ({ evidence }: InvestigationRunEvidenceProps) => {
  const { t_i18n } = useFormatter();
  const [showAll, setShowAll] = useState(false);
  const numbers = citationNumbers(evidence);
  const visible = showAll ? evidence : evidence.slice(0, VISIBLE_EVIDENCE);
  return (
    <Card title={`${t_i18n('Evidence')} (${evidence.length})`}>
      {evidence.length === 0 ? (
        <Typography variant="body2" color="text.secondary">{t_i18n('No evidence was collected yet.')}</Typography>
      ) : (
        <Stack spacing={1}>
          <Box component="ol" sx={{ listStyle: 'none', margin: 0, padding: 0 }} aria-label={t_i18n('Cited evidence')}>
            {visible.map((item) => (
              <Box component="li" key={item.id} id={`investigation-evidence-${numbers.get(item.id)}`} sx={{ paddingY: 0.5 }} data-testid="investigation-evidence">
                <Stack direction="row" spacing={1.5} alignItems="center">
                  <Typography variant="body2" color="text.secondary" sx={{ minWidth: 32 }}>{`[${numbers.get(item.id)}]`}</Typography>
                  <ItemIcon type={item.entity_type} size="small" />
                  <Box sx={{ flex: 1, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {item.in_draft
                      ? <span>{item.name ?? item.id}</span>
                      : <Link to={elementPath(item.id)}>{item.name ?? item.id}</Link>}
                    <Typography component="span" variant="caption" color="text.secondary" sx={{ marginLeft: 1 }}>
                      {t_i18n(`entity_${item.entity_type}`)}
                    </Typography>
                  </Box>
                  <Chip label={t_i18n(EVIDENCE_ORIGIN_LABELS[item.origin] ?? item.origin)} size="sm" />
                  {item.in_draft && <Chip label={t_i18n('In draft')} severity="info" size="sm" />}
                </Stack>
              </Box>
            ))}
          </Box>
          {evidence.length > VISIBLE_EVIDENCE && (
            <Box>
              <Button size="small" variant="tertiary" onClick={() => setShowAll(!showAll)}>
                {showAll ? t_i18n('Show less') : `${t_i18n('Show all')} (${evidence.length})`}
              </Button>
            </Box>
          )}
        </Stack>
      )}
    </Card>
  );
};

export default InvestigationRunEvidence;
