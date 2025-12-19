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

import Typography from '@mui/material/Typography';
import Box from '@mui/material/Box';
import Tooltip from '@mui/material/Tooltip';
import { Link } from 'react-router-dom';
import React from 'react';
import { graphql, useFragment } from 'react-relay';
import { useTheme } from '@mui/material/styles';
import { pirLogRedirectUri } from '@components/pir/pir-history-utils';
import PirHistoryMessage from '../PirHistoryMessage';
import type { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import { displayEntityTypeForTranslation } from '../../../../utils/String';
import ItemIcon from '../../../../components/ItemIcon';
import { PirOverviewHistoryPirFragment$key } from './__generated__/PirOverviewHistoryPirFragment.graphql';
import { PirOverviewHistoryFragment$key } from './__generated__/PirOverviewHistoryFragment.graphql';
import Paper from '../../../../components/Paper';

const pirFragment = graphql`
  fragment PirOverviewHistoryPirFragment on Pir {
    id
    name
  }
`;

const pirHistoryFragment = graphql`
  fragment PirOverviewHistoryFragment on Query {
    pirLogs(
      pirId: $pirId
      first: $first
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
      search: $search
    ) {
      edges {
        node {
          id
          event_scope
          timestamp
          user {
            name
          }
          entity_type
          context_data {
            entity_id
            entity_type
            entity_name
            message
            pir_score
            pir_match_from
            from_id
            to_id
          }
        }
      }
    }
  }
`;

interface PirOverviewHistoryProps {
  dataHistory: PirOverviewHistoryFragment$key;
  dataPir: PirOverviewHistoryPirFragment$key;
}

const PirOverviewHistory = ({ dataHistory, dataPir }: PirOverviewHistoryProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n, nsdt } = useFormatter();

  const pir = useFragment(pirFragment, dataPir);
  const { pirLogs } = useFragment(pirHistoryFragment, dataHistory);
  const history = (pirLogs?.edges ?? []).flatMap((e) => e?.node ?? []);

  return (
    <Paper
      title={t_i18n('News feed')}
      style={{ maxHeight: '899px', overflow: 'auto' }}
    >
      <div style={{ display: 'flex', gap: theme.spacing(0.5), flexDirection: 'column' }}>
        {history.length === 0 && (
          <Typography variant="body2">
            {t_i18n('No recent history for this PIR')}
          </Typography>
        )}

        {history.map((historyItem) => {
          const { id, context_data, timestamp } = historyItem;
          const redirectURI = pirLogRedirectUri(context_data);

          return (
            <Box
              key={id}
              sx={{
                padding: 1,
                borderRadius: 1,
                '&:hover': { background: theme.palette.background.accent },
              }}
            >
              <Link
                to={redirectURI}
                style={{
                  color: 'inherit',
                  display: 'flex',
                  gap: theme.spacing(2),
                  alignItems: 'center',
                }}
              >
                <Tooltip title={t_i18n(displayEntityTypeForTranslation(context_data?.entity_type ?? ''))}>
                  <div>
                    <ItemIcon type={context_data?.entity_type} />
                  </div>
                </Tooltip>
                <div>
                  <Typography variant="body2" color={theme.palette.text?.secondary}>
                    {nsdt(timestamp)}
                  </Typography>
                  <PirHistoryMessage
                    log={historyItem}
                    pirName={pir.name}
                  />
                </div>
              </Link>
            </Box>
          );
        })}
      </div>
    </Paper>
  );
};

export default PirOverviewHistory;
