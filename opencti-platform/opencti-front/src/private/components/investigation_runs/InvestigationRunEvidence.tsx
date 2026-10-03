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
import { DescriptionOutlined, LanguageOutlined, TerminalOutlined } from '@mui/icons-material';
import { Chip } from '@filigran/design-system';
import Card from '@common/card/Card';
import Button from '@common/button/Button';
import ItemIcon from '../../../components/ItemIcon';
import { useFormatter } from '../../../components/i18n';
import { citationNumbers, EVIDENCE_KIND_LABELS, evidenceHref, evidenceObjectPath, isRunActive } from './investigationRunUtils';
import type { InvestigationRunView_run$data } from './__generated__/InvestigationRunView_run.graphql';

const VISIBLE_EVIDENCE = 25;

type Evidence = InvestigationRunView_run$data['evidence'][number];

const KindIcon = ({ item }: { item: Evidence }) => {
  if (item.kind === 'opencti_object') return <ItemIcon type={item.entity_type ?? 'Unknown'} size="small" />;
  if (item.kind === 'url') return <LanguageOutlined fontSize="small" color="action" />;
  if (item.kind === 'document') return <DescriptionOutlined fontSize="small" color="action" />;
  return <TerminalOutlined fontSize="small" color="action" />;
};

// An OpenCTI object links to the entity itself (never through an address),
// a web page to its address, a document or a tool result is plain text.
const EvidenceLabel = ({ item }: { item: Evidence }) => {
  const objectPath = item.in_draft ? null : evidenceObjectPath(item);
  if (objectPath) return <Link to={objectPath}>{item.label}</Link>;
  const href = evidenceHref(item);
  if (href) return <a href={href} target="_blank" rel="noopener noreferrer">{item.label}</a>;
  return <span>{item.label}</span>;
};

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
            {visible.map((item) => (
              <Box component="li" key={item.id} id={`investigation-evidence-${numbers.get(item.id)}`} sx={{ paddingY: 0.5 }} data-testid="investigation-evidence">
                <Stack direction="row" spacing={1.5} alignItems="center">
                  <Typography variant="body2" color="text.secondary" sx={{ minWidth: 32 }}>{`[${numbers.get(item.id)}]`}</Typography>
                  <KindIcon item={item} />
                  <Box sx={{ flex: 1, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    <EvidenceLabel item={item} />
                    {item.kind === 'opencti_object' && item.entity_type && (
                      <Typography component="span" variant="caption" color="text.secondary" sx={{ marginLeft: 1 }}>
                        {t_i18n(`entity_${item.entity_type}`)}
                      </Typography>
                    )}
                  </Box>
                  <Chip label={t_i18n(EVIDENCE_KIND_LABELS[item.kind] ?? item.kind)} />
                  {item.in_draft && <Chip label={t_i18n('In draft')} severity="info" />}
                </Stack>
                {item.quote && (
                  <Typography variant="caption" color="text.secondary" component="blockquote" sx={{ margin: 0, marginLeft: 6, fontStyle: 'italic' }}>
                    {item.quote}
                  </Typography>
                )}
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
