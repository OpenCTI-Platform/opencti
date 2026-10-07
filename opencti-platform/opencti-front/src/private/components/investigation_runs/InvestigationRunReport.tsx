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
import Card from '@common/card/Card';
import { useFormatter } from '../../../components/i18n';
import MarkdownDisplay from '../../../components/markdownDisplay/MarkdownDisplay';
import { evidenceHref, isReportInDraft, isRunActive } from './investigationRunUtils';
import type { InvestigationRunView_run$data } from './__generated__/InvestigationRunView_run.graphql';

interface InvestigationRunReportProps {
  run: InvestigationRunView_run$data;
}

/** The cited report the engine wrote last, with the sources it cites, and the summary of its conclusion. */
const InvestigationRunReport = ({ run }: InvestigationRunReportProps) => {
  const { t_i18n } = useFormatter();
  const sources = [...run.report_sources].sort((a, b) => a.n - b.n);
  const inDraft = isReportInDraft(run);
  let emptyText = t_i18n('No report was written: the investigation found nothing it could cite.');
  if (isRunActive(run.run_status)) emptyText = t_i18n('The report is written once the investigation has weighed its hypotheses.');
  return (
    <Card title={t_i18n('Report')}>
      <Stack spacing={2} data-testid="investigation-report">
        {run.summary && (
          <Box>
            <Typography variant="h4" gutterBottom>{t_i18n('Summary')}</Typography>
            <MarkdownDisplay content={run.summary} remarkGfmPlugin commonmark />
          </Box>
        )}
        {run.report ? (
          <MarkdownDisplay content={run.report} remarkGfmPlugin commonmark />
        ) : (
          <Typography variant="body2" color="text.secondary">{emptyText}</Typography>
        )}
        {sources.length > 0 && (
          <Box>
            <Typography variant="h4" gutterBottom>{t_i18n('Sources')}</Typography>
            <Box component="ol" sx={{ listStyle: 'none', margin: 0, padding: 0 }} aria-label={t_i18n('Sources')}>
              {sources.map((source) => {
                const href = evidenceHref({ id: String(source.n), kind: 'url', href: source.href });
                return (
                  <Box component="li" key={source.n} sx={{ paddingY: 0.25 }}>
                    <Typography component="span" variant="body2" color="text.secondary" sx={{ marginRight: 1 }}>{`[${source.n}]`}</Typography>
                    {href ? <a href={href} target="_blank" rel="noopener noreferrer">{source.label}</a> : <span>{source.label}</span>}
                  </Box>
                );
              })}
            </Box>
          </Box>
        )}
        {run.report_id && (
          <Typography variant="body2">
            {inDraft && run.draft
              ? <Link to={`/dashboard/data/import/draft/${run.draft.id}`}>{t_i18n('The report is in the investigation draft')}</Link>
              : <Link to={`/dashboard/analyses/reports/${run.report_id}`}>{t_i18n('Open the report')}</Link>}
          </Typography>
        )}
      </Stack>
    </Card>
  );
};

export default InvestigationRunReport;
