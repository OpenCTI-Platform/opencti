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
import { Chip } from '@filigran/design-system';
import Card from '@common/card/Card';
import Button from '@common/button/Button';
import { useFormatter } from '../../../components/i18n';
import { CONFIDENCE_LABELS, elementPath, emptySectionSentence, PRIORITY_LABELS, prioritySeverity } from './investigationRunUtils';
import type { InvestigationRunView_run$data } from './__generated__/InvestigationRunView_run.graphql';

type Run = InvestigationRunView_run$data;

// Recommendations shown in the summary; the Recommendations section holds them all.
const TOP_RECOMMENDATIONS = 3;

interface InvestigationRunConclusionProps {
  run: Run;
  onOpenReport: () => void;
}

/** What the investigation concluded, at a glance: the leading hypothesis, the first recommendations and the report. */
const InvestigationRunConclusion = ({ run, onOpenReport }: InvestigationRunConclusionProps) => {
  const { t_i18n } = useFormatter();
  const leading = run.hypotheses.find((hypothesis) => hypothesis.rank === 1) ?? run.hypotheses[0];
  const recommendations = run.recommendations.slice(0, TOP_RECOMMENDATIONS);
  const hasReport = !!run.report || !!run.summary;
  const empty = !leading && recommendations.length === 0 && !hasReport;
  return (
    <Card title={t_i18n('Conclusion')}>
      <Stack spacing={2} data-testid="investigation-run-conclusion">
        {empty && (
          <Typography variant="body2" color="text.secondary">
            {emptySectionSentence(run, t_i18n, t_i18n('The conclusion appears once the investigation has weighed its hypotheses.'), t_i18n('No conclusion was written.'))}
          </Typography>
        )}
        {leading && (
          <Stack spacing={0.75}>
            <Typography variant="caption" color="text.secondary">{t_i18n('Leading hypothesis')}</Typography>
            <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
              <Link to={elementPath(leading.candidate_id)}>{leading.candidate_name ?? t_i18n('Unknown actor')}</Link>
              <Chip
                size="sm"
                severity={leading.confidence !== null && leading.confidence !== undefined ? 'info' : 'neutral'}
                label={leading.confidence_label && leading.confidence !== null && leading.confidence !== undefined
                  ? t_i18n('{label} ({confidence}%)', { values: { label: t_i18n(CONFIDENCE_LABELS[leading.confidence_label] ?? 'Roughly even chance'), confidence: leading.confidence } })
                  : t_i18n('Not assessed')}
              />
            </Stack>
          </Stack>
        )}
        {recommendations.length > 0 && (
          <Stack spacing={0.75}>
            <Typography variant="caption" color="text.secondary">{t_i18n('Recommendations')}</Typography>
            <Box component="ol" sx={{ margin: 0, paddingLeft: 2.5 }}>
              {recommendations.map((recommendation) => (
                <Box component="li" key={recommendation.id} sx={{ paddingY: 0.25 }}>
                  <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
                    <Typography variant="body2">{recommendation.text}</Typography>
                    <Chip size="sm" label={t_i18n(PRIORITY_LABELS[recommendation.priority] ?? 'Medium priority')} severity={prioritySeverity(recommendation.priority)} />
                  </Stack>
                </Box>
              ))}
            </Box>
          </Stack>
        )}
        {hasReport && (
          <Box>
            <Button size="small" variant="secondary" onClick={onOpenReport} data-testid="investigation-conclusion-report">{t_i18n('Open the report')}</Button>
          </Box>
        )}
      </Stack>
    </Card>
  );
};

export default InvestigationRunConclusion;
