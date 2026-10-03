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
import Card from '@common/card/Card';
import Button from '@common/button/Button';
import ItemIcon from '../../../components/ItemIcon';
import { useFormatter } from '../../../components/i18n';
import { elementPath } from './investigationRunUtils';
import type { InvestigationRunView_run$data } from './__generated__/InvestigationRunView_run.graphql';

const VISIBLE_EVENTS = 30;

interface InvestigationRunTimelineProps {
  timeline: InvestigationRunView_run$data['timeline'];
}

/** Reconstructed from the creation, first and last seen dates of the evidence. */
const InvestigationRunTimeline = ({ timeline }: InvestigationRunTimelineProps) => {
  const { t_i18n, fldt } = useFormatter();
  const [showAll, setShowAll] = useState(false);
  const events = [...timeline].sort((a, b) => new Date(a.ts).getTime() - new Date(b.ts).getTime());
  const visible = showAll ? events : events.slice(0, VISIBLE_EVENTS);
  return (
    <Card title={`${t_i18n('Timeline')} (${events.length})`}>
      {events.length === 0 ? (
        <Typography variant="body2" color="text.secondary">{t_i18n('The timeline is built when the investigation concludes.')}</Typography>
      ) : (
        <Stack spacing={1}>
          <Box component="ol" sx={{ listStyle: 'none', margin: 0, padding: 0, borderLeft: 2, borderColor: 'divider' }}>
            {visible.map((event, index) => (
              <Box component="li" key={`${event.entity_id}-${event.ts}-${index}`} sx={{ paddingLeft: 2, paddingY: 0.75 }} data-testid="investigation-timeline-event">
                <Typography variant="caption" color="text.secondary">{fldt(event.ts)}</Typography>
                <Stack direction="row" spacing={1} alignItems="center">
                  <ItemIcon type={event.entity_type} size="small" />
                  <Typography variant="body2">
                    {`${event.event} - `}
                    <Link to={elementPath(event.entity_id)}>{event.name ?? event.entity_id}</Link>
                  </Typography>
                </Stack>
              </Box>
            ))}
          </Box>
          {events.length > VISIBLE_EVENTS && (
            <Box>
              <Button size="small" variant="tertiary" onClick={() => setShowAll(!showAll)}>
                {showAll ? t_i18n('Show less') : `${t_i18n('Show all')} (${events.length})`}
              </Button>
            </Box>
          )}
        </Stack>
      )}
    </Card>
  );
};

export default InvestigationRunTimeline;
