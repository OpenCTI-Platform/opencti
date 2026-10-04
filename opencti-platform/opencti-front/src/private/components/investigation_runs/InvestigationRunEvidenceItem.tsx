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
import { Chip, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import Button from '@common/button/Button';
import ItemIcon from '../../../components/ItemIcon';
import { useFormatter } from '../../../components/i18n';
import { EVIDENCE_KIND_LABELS, evidenceHref, evidenceObjectPath } from './investigationRunUtils';
import type { InvestigationRunView_run$data } from './__generated__/InvestigationRunView_run.graphql';

export type Evidence = InvestigationRunView_run$data['evidence'][number];

// A quote longer than this is clamped to three lines with "Show more".
const LONG_QUOTE = 240;

const KindIcon = ({ item, label }: { item: Evidence; label: string }) => {
  if (item.kind === 'opencti_object') return <ItemIcon type={item.entity_type ?? 'Unknown'} size="small" />;
  if (item.kind === 'url') return <LanguageOutlined fontSize="small" color="action" titleAccess={label} />;
  if (item.kind === 'document') return <DescriptionOutlined fontSize="small" color="action" titleAccess={label} />;
  return <TerminalOutlined fontSize="small" color="action" titleAccess={label} />;
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

interface InvestigationRunEvidenceItemProps {
  item: Evidence;
  number: number | undefined;
}

/** One cited piece of evidence: its citation number, its kind, a link and the quoted passage. */
const InvestigationRunEvidenceItem = ({ item, number }: InvestigationRunEvidenceItemProps) => {
  const { t_i18n } = useFormatter();
  const [expanded, setExpanded] = useState(false);
  const kindLabel = t_i18n(EVIDENCE_KIND_LABELS[item.kind] ?? 'Tool result');
  const longQuote = (item.quote?.length ?? 0) > LONG_QUOTE;
  return (
    <Box component="li" id={number ? `investigation-evidence-${number}` : undefined} sx={{ paddingY: 0.75 }} data-testid="investigation-evidence">
      <Stack direction="row" spacing={1.5} alignItems="flex-start">
        <Typography variant="body2" color="text.secondary" sx={{ minWidth: 32, fontVariantNumeric: 'tabular-nums' }}>
          {number ? `[${number}]` : ''}
        </Typography>
        <Box sx={{ display: 'inline-flex', paddingTop: '2px' }}><KindIcon item={item} label={kindLabel} /></Box>
        <Stack spacing={0.5} sx={{ flex: 1, minWidth: 0 }}>
          <Stack direction="row" spacing={1} alignItems="center" sx={{ minWidth: 0 }}>
            <Tooltip>
              <TooltipTrigger asChild>
                <Box sx={{ minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  <EvidenceLabel item={item} />
                </Box>
              </TooltipTrigger>
              <TooltipContent>{item.label}</TooltipContent>
            </Tooltip>
            <Typography component="span" variant="caption" color="text.secondary" sx={{ flexShrink: 0 }}>
              {item.kind === 'opencti_object' && item.entity_type ? t_i18n(`entity_${item.entity_type}`) : kindLabel}
            </Typography>
            {item.in_draft && <Chip label={t_i18n('In draft')} severity="info" size="sm" />}
          </Stack>
          {item.quote && (
            <Box>
              <Typography
                variant="body2"
                color="text.secondary"
                component="blockquote"
                sx={{
                  margin: 0,
                  fontStyle: 'italic',
                  // Only a quote that can be expanded is clamped: a short one always shows in full.
                  ...(longQuote && !expanded ? { display: '-webkit-box', WebkitLineClamp: 3, WebkitBoxOrient: 'vertical', overflow: 'hidden' } : {}),
                }}
              >
                {item.quote}
              </Typography>
              {longQuote && (
                <Button size="small" variant="tertiary" onClick={() => setExpanded(!expanded)} aria-expanded={expanded}>
                  {expanded ? t_i18n('Show less') : t_i18n('Show more')}
                </Button>
              )}
            </Box>
          )}
        </Stack>
      </Stack>
    </Box>
  );
};

export default InvestigationRunEvidenceItem;
