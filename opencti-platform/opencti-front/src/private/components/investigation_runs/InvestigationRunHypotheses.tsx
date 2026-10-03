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

import React from 'react';
import { Link } from 'react-router';
import Box from '@mui/material/Box';
import Stack from '@mui/material/Stack';
import Typography from '@mui/material/Typography';
import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';
import { alpha, useTheme } from '@mui/material/styles';
import { Chip, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import Card from '@common/card/Card';
import { useFormatter } from '../../../components/i18n';
import InvestigationRunFeedback from './InvestigationRunFeedback';
import {
  citationNumbers,
  CONFIDENCE_LABELS,
  consistencyOf,
  elementPath,
  EVIDENCE_CATEGORY_LABELS,
  evidenceObjectPath,
  feedbackDecisionFor,
  formatProbability,
  isRunActive,
} from './investigationRunUtils';
import type { InvestigationRunView_run$data } from './__generated__/InvestigationRunView_run.graphql';

type Hypothesis = InvestigationRunView_run$data['hypotheses'][number];
type EvidenceCell = Hypothesis['evidence'][number];

interface InvestigationRunHypothesesProps {
  run: InvestigationRunView_run$data;
}

const ConsistencyCell = ({ cell }: { cell: EvidenceCell }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const scale = consistencyOf(cell.consistency);
  let color = theme.palette.text.secondary;
  if (cell.consistency > 0) color = theme.palette.success.main;
  if (cell.consistency < 0) color = theme.palette.error.main;
  const description = `${t_i18n(scale.label)} - ${t_i18n(EVIDENCE_CATEGORY_LABELS[cell.category] ?? cell.category)}`;
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Box
          component="span"
          tabIndex={0}
          aria-label={description}
          sx={{
            display: 'inline-block',
            minWidth: 36,
            paddingX: 1,
            paddingY: 0.25,
            borderRadius: 1,
            textAlign: 'center',
            fontWeight: 600,
            color,
            backgroundColor: alpha(color, Math.min(0.3, 0.08 + Math.abs(cell.consistency) * 0.08)),
          }}
        >
          {scale.code}
        </Box>
      </TooltipTrigger>
      <TooltipContent>
        <Stack spacing={0.5}>
          <span>{description}</span>
          <span>{`${t_i18n('Weight')}: ${cell.weight.toFixed(2)} - ${t_i18n('Diagnosticity')}: ${cell.diagnosticity.toFixed(2)}`}</span>
          {cell.rationale && <span>{cell.rationale}</span>}
        </Stack>
      </TooltipContent>
    </Tooltip>
  );
};

/**
 * Analysis of Competing Hypotheses: candidates in columns, cited evidence in
 * rows. The engine proposes the links; OpenCTI computes the scores shown here.
 */
const InvestigationRunHypotheses = ({ run }: InvestigationRunHypothesesProps) => {
  const { t_i18n } = useFormatter();
  const { hypotheses } = run;
  const numbers = citationNumbers(run.evidence);
  const evidenceById = new Map(run.evidence.map((item) => [item.id, item]));
  const rows: { id: string; name: string; path: string | null }[] = [];
  hypotheses.forEach((hypothesis) => hypothesis.evidence.forEach((cell) => {
    if (!rows.some((row) => row.id === cell.evidence_id)) {
      const item = evidenceById.get(cell.evidence_id);
      rows.push({
        id: cell.evidence_id,
        name: cell.evidence_name ?? item?.label ?? cell.evidence_id,
        path: item ? (!item.in_draft && evidenceObjectPath(item)) || null : elementPath(cell.evidence_id),
      });
    }
  }));
  rows.sort((a, b) => (numbers.get(a.id) ?? Number.MAX_SAFE_INTEGER) - (numbers.get(b.id) ?? Number.MAX_SAFE_INTEGER));
  const threshold = run.policy?.attribution_min_confidence;
  return (
    <Card title={`${t_i18n('Hypotheses')} (${hypotheses.length})`}>
      {hypotheses.length === 0 ? (
        <Typography variant="body2" color="text.secondary">
          {isRunActive(run.run_status) ? t_i18n('Hypotheses appear once the evidence is linked to candidate threats.') : t_i18n('No attribution hypothesis was proposed.')}
        </Typography>
      ) : (
        <Stack spacing={2}>
          {threshold !== undefined && threshold !== null && (
            <Typography variant="body2" color="text.secondary">
              {t_i18n('An attribution is written to the draft when the leading hypothesis reaches {threshold}% confidence.', { values: { threshold } })}
            </Typography>
          )}
          <Box sx={{ overflowX: 'auto' }}>
            <Table size="small" aria-label={t_i18n('Analysis of competing hypotheses')} data-testid="investigation-ach-matrix">
              <TableHead>
                <TableRow>
                  <TableCell>{t_i18n('Evidence')}</TableCell>
                  {hypotheses.map((hypothesis) => (
                    <TableCell key={hypothesis.candidate_id} align="center" sx={{ minWidth: 160 }}>
                      <Stack spacing={0.5} alignItems="center">
                        <span>
                          {`#${hypothesis.rank} `}
                          <Link to={elementPath(hypothesis.candidate_id)}>{hypothesis.candidate_name ?? hypothesis.candidate_id}</Link>
                        </span>
                        <Typography variant="h3" component="span">{formatProbability(hypothesis.probability)}</Typography>
                        <Chip
                          label={hypothesis.confidence_label && hypothesis.confidence !== null && hypothesis.confidence !== undefined
                            ? `${t_i18n(CONFIDENCE_LABELS[hypothesis.confidence_label] ?? hypothesis.confidence_label)} (${hypothesis.confidence}%)`
                            : t_i18n('Not assessed')}
                          severity={hypothesis.rank === 1 && hypothesis.confidence !== null ? 'info' : 'neutral'}
                          size="sm"
                        />
                      </Stack>
                    </TableCell>
                  ))}
                </TableRow>
              </TableHead>
              <TableBody>
                {rows.map((row) => (
                  <TableRow key={row.id}>
                    <TableCell>
                      <Typography component="span" variant="body2" color="text.secondary" sx={{ marginRight: 1 }}>
                        {numbers.has(row.id) ? `[${numbers.get(row.id)}]` : ''}
                      </Typography>
                      {row.path ? <Link to={row.path}>{row.name}</Link> : <span>{row.name}</span>}
                    </TableCell>
                    {hypotheses.map((hypothesis) => {
                      const cell = hypothesis.evidence.find((item) => item.evidence_id === row.id);
                      return (
                        <TableCell key={hypothesis.candidate_id} align="center">
                          {cell ? <ConsistencyCell cell={cell} /> : (
                            <Typography component="span" variant="caption" color="text.disabled">{t_i18n('Not assessed')}</Typography>
                          )}
                        </TableCell>
                      );
                    })}
                  </TableRow>
                ))}
                <TableRow>
                  <TableCell>{t_i18n('Your assessment')}</TableCell>
                  {hypotheses.map((hypothesis) => (
                    <TableCell key={hypothesis.candidate_id} align="center">
                      <InvestigationRunFeedback
                        runId={run.id}
                        itemType="hypothesis"
                        itemRef={hypothesis.candidate_id}
                        itemLabel={hypothesis.candidate_name ?? hypothesis.candidate_id}
                        decision={feedbackDecisionFor(run.analyst_feedback, 'hypothesis', hypothesis.candidate_id)}
                      />
                    </TableCell>
                  ))}
                </TableRow>
              </TableBody>
            </Table>
          </Box>
          <Stack spacing={1}>
            {hypotheses.map((hypothesis) => (
              <Box key={hypothesis.candidate_id}>
                <Typography variant="body2" sx={{ fontWeight: 600 }}>
                  {`#${hypothesis.rank} ${hypothesis.candidate_name ?? hypothesis.candidate_id}`}
                </Typography>
                <Typography variant="body2">{hypothesis.explanation}</Typography>
                {hypothesis.rationale && <Typography variant="body2" color="text.secondary">{hypothesis.rationale}</Typography>}
              </Box>
            ))}
          </Stack>
        </Stack>
      )}
    </Card>
  );
};

export default InvestigationRunHypotheses;
