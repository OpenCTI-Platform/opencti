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
import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';
import { Chip, type ChipSeverity, Tabs, TabsList, TabsTrigger } from '@filigran/design-system';
import Card from '@common/card/Card';
import Button from '@common/button/Button';
import { useFormatter } from '../../../components/i18n';
import { elementPath, ENRICHMENT_STATUS_LABELS, formatDuration } from './investigationRunUtils';
import type { InvestigationRunView_run$data } from './__generated__/InvestigationRunView_run.graphql';

const VISIBLE_ROWS = 50;

const LEDGER_STATUS_SEVERITIES: Record<string, ChipSeverity> = { done: 'low', failed: 'high', skipped: 'neutral' };
const LEDGER_STATUS_LABELS: Record<string, string> = { done: 'Done', failed: 'Failed', skipped: 'Skipped' };
const ENRICHMENT_SEVERITIES: Record<string, ChipSeverity> = {
  completed: 'low',
  failed: 'high',
  timeout: 'high',
  rejected: 'neutral',
  skipped: 'neutral',
  awaiting_approval: 'medium',
  queued: 'info',
  dispatched: 'info',
};

interface InvestigationRunLedgerProps {
  steps: InvestigationRunView_run$data['steps'];
  enrichmentRequests: InvestigationRunView_run$data['enrichment_requests'];
}

/** Every step of the run, newest first, with what it cost: the audit trail of the investigation. */
const InvestigationRunLedger = ({ steps, enrichmentRequests }: InvestigationRunLedgerProps) => {
  const { t_i18n, nsdt } = useFormatter();
  const [tab, setTab] = useState<'ledger' | 'enrichments'>('ledger');
  const [showAll, setShowAll] = useState(false);
  const visibleSteps = showAll ? steps : steps.slice(0, VISIBLE_ROWS);
  return (
    <Card title={t_i18n('Investigation ledger')}>
      <Stack spacing={2}>
        <Tabs value={tab} onValueChange={(value) => setTab(value as 'ledger' | 'enrichments')}>
          <TabsList>
            <TabsTrigger value="ledger">{`${t_i18n('Steps')} (${steps.length})`}</TabsTrigger>
            <TabsTrigger value="enrichments">{`${t_i18n('Enrichments')} (${enrichmentRequests.length})`}</TabsTrigger>
          </TabsList>
        </Tabs>
        {tab === 'ledger' && (
          <Box sx={{ overflowX: 'auto' }}>
            <Table size="small" aria-label={t_i18n('Investigation ledger')} data-testid="investigation-ledger">
              <TableHead>
                <TableRow>
                  <TableCell>{t_i18n('Date')}</TableCell>
                  <TableCell>{t_i18n('Iteration')}</TableCell>
                  <TableCell>{t_i18n('Tool')}</TableCell>
                  <TableCell>{t_i18n('Description')}</TableCell>
                  <TableCell>{t_i18n('Status')}</TableCell>
                  <TableCell align="right">{t_i18n('Duration')}</TableCell>
                  <TableCell align="right">{t_i18n('Cost')}</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {visibleSteps.map((step) => (
                  <TableRow key={step.id}>
                    <TableCell sx={{ whiteSpace: 'nowrap' }}>{nsdt(step.started_at)}</TableCell>
                    <TableCell>{step.iteration}</TableCell>
                    <TableCell sx={{ fontFamily: 'monospace' }}>{step.tool}</TableCell>
                    <TableCell>
                      <span>{step.description}</span>
                      {step.error && <Typography variant="caption" color="error" display="block">{step.error}</Typography>}
                    </TableCell>
                    <TableCell>
                      <Chip label={t_i18n(LEDGER_STATUS_LABELS[step.status] ?? step.status)} severity={LEDGER_STATUS_SEVERITIES[step.status] ?? 'neutral'} size="sm" />
                    </TableCell>
                    <TableCell align="right" sx={{ whiteSpace: 'nowrap' }}>{formatDuration(step.duration_ms)}</TableCell>
                    <TableCell align="right">{step.cost_units}</TableCell>
                  </TableRow>
                ))}
                {steps.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={7}>{t_i18n('No step was recorded yet.')}</TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
            {steps.length > VISIBLE_ROWS && (
              <Button size="small" variant="tertiary" onClick={() => setShowAll(!showAll)}>
                {showAll ? t_i18n('Show less') : `${t_i18n('Show all')} (${steps.length})`}
              </Button>
            )}
          </Box>
        )}
        {tab === 'enrichments' && (
          <Box sx={{ overflowX: 'auto' }}>
            <Table size="small" aria-label={t_i18n('Enrichments')} data-testid="investigation-enrichments">
              <TableHead>
                <TableRow>
                  <TableCell>{t_i18n('Date')}</TableCell>
                  <TableCell>{t_i18n('Entity')}</TableCell>
                  <TableCell>{t_i18n('Connector')}</TableCell>
                  <TableCell>{t_i18n('Reason')}</TableCell>
                  <TableCell>{t_i18n('Status')}</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {enrichmentRequests.map((request) => (
                  <TableRow key={request.id}>
                    <TableCell sx={{ whiteSpace: 'nowrap' }}>{nsdt(request.created_at)}</TableCell>
                    <TableCell><Link to={elementPath(request.entity_id)}>{request.entity_id}</Link></TableCell>
                    <TableCell>{request.connector_name ?? request.connector_id}</TableCell>
                    <TableCell>{request.reason ?? '-'}</TableCell>
                    <TableCell>
                      <Chip
                        label={t_i18n(ENRICHMENT_STATUS_LABELS[request.status] ?? request.status)}
                        severity={ENRICHMENT_SEVERITIES[request.status] ?? 'neutral'}
                        size="sm"
                      />
                    </TableCell>
                  </TableRow>
                ))}
                {enrichmentRequests.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={5}>{t_i18n('No enrichment was requested.')}</TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </Box>
        )}
      </Stack>
    </Card>
  );
};

export default InvestigationRunLedger;
