import Typography from '@mui/material/Typography';
import Avatar from '@mui/material/Avatar';
import Box from '@mui/material/Box';
import Tooltip from '@mui/material/Tooltip';
import { Link } from 'react-router-dom';
import React from 'react';
import { deepOrange, green, indigo, pink, red, teal, yellow } from '@mui/material/colors';
import { AddOutlined, DeleteOutlined, EditOutlined, HelpOutlined } from '@mui/icons-material';
import { LinkVariantPlus, LinkVariantRemove, Merge } from 'mdi-material-ui';
import { graphql, useFragment } from 'react-relay';
import { useTheme } from '@mui/material/styles';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';
import { isNotEmptyField } from '../../../../utils/utils';
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
    logs(
      first: $first
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
      search: $search
    ) {
      edges {
        node {
          id
          event_type
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
            commit
            external_references {
              id
              source_name
              external_id
              url
              description
            }
          }
        }
      }
    }
  }
`;

const HISTORY_ICON_CONFIG = {
  create: {
    color: pink[500],
    icon: <AddOutlined sx={{ fontSize: 14 }} />,
  },
  delete: {
    color: red[500],
    icon: <DeleteOutlined sx={{ fontSize: 14 }} />,
  },
  merge: {
    color: teal[500],
    icon: <Merge sx={{ fontSize: 14 }} />,
  },
  updateReplaces: {
    color: green[500],
    icon: <EditOutlined sx={{ fontSize: 14 }} />,
  },
  updateChanges: {
    color: green[500],
    icon: <EditOutlined sx={{ fontSize: 14 }} />,
  },
  updateAdds: {
    color: indigo[500],
    icon: <LinkVariantPlus sx={{ fontSize: 14 }} />,
  },
  updateRemoves: {
    color: deepOrange[500],
    icon: <LinkVariantRemove sx={{ fontSize: 14 }} />,
  },
  default: {
    color: yellow[500],
    icon: <HelpOutlined sx={{ fontSize: 14 }} />,
  },
};

interface PirOverviewHistoryProps {
  dataHistory: PirOverviewHistoryFragment$key
  dataPir: PirOverviewHistoryPirFragment$key
}

const PirOverviewHistory = ({ dataHistory, dataPir }: PirOverviewHistoryProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n, nsdt } = useFormatter();

  const pir = useFragment(pirFragment, dataPir);
  const { logs } = useFragment(pirHistoryFragment, dataHistory);
  const history = (logs?.edges ?? []).flatMap((e) => e?.node ?? []);

  const getIconConfig = ({ event_scope, context_data }: typeof history[0]) => {
    if (event_scope === 'create') return HISTORY_ICON_CONFIG.create;
    if (event_scope === 'merge') return HISTORY_ICON_CONFIG.merge;
    if (event_scope === 'delete') return HISTORY_ICON_CONFIG.delete;
    if (event_scope === 'update') {
      const { message } = context_data ?? {};
      if (message?.includes('replaces')) return HISTORY_ICON_CONFIG.updateReplaces;
      if (message?.includes('changes')) return HISTORY_ICON_CONFIG.updateChanges;
      if (message?.includes('adds')) return HISTORY_ICON_CONFIG.updateAdds;
      if (message?.includes('removes')) return HISTORY_ICON_CONFIG.updateRemoves;
    }
    return HISTORY_ICON_CONFIG.default;
  };

  const getHistoryMessage = ({ context_data, entity_type, event_scope, user }: typeof history[0]) => {
    const message = context_data?.message ?? '';
    const entityType = t_i18n(displayEntityTypeForTranslation(context_data?.entity_type ?? ''));

    if (message.match(/adds .+ in `In PIR`/)) {
      return t_i18n('', {
        id: '{entityType} `{entityName}` added to `{pirName}`',
        values: {
          entityType,
          entityName: context_data?.entity_name,
          pirName: pir.name,
        },
      });
    }
    if (message.match(/removes .+ in `In PIR`/)) {
      return t_i18n('', {
        id: '{entityType} `{entityName}` removed from `{pirName}`',
        values: {
          entityType,
          entityName: context_data?.entity_name,
          pirName: pir.name,
        },
      });
    }

    const isUpdate = entity_type === 'History'
      && event_scope === 'update'
      && isNotEmptyField(context_data?.entity_name);

    // Default message
    return `\`${user?.name}\` ${message} ${isUpdate ? `for \`${context_data?.entity_name}\` (${entityType})` : ''}`;
  };

  return (
    <Paper title={t_i18n('News feed')}>
      <div style={{ display: 'flex', gap: theme.spacing(0.5), flexDirection: 'column' }}>
        {history.length === 0 && (
        <Typography variant='body2'>
          {t_i18n('No recent history for this PIR')}
        </Typography>
        )}

        {history.map((historyItem) => {
          const { id, context_data, timestamp } = historyItem;
          const { color, icon } = getIconConfig(historyItem);
          const historyMessage = getHistoryMessage(historyItem);

          const isAddInPir = /adds .+ in `In PIR`/.test(context_data?.message ?? '');
          let redirectURI = `/dashboard/id/${context_data?.entity_id}`;
          if (isAddInPir) {
            const addInPirFilters = context_data?.entity_id
              ? JSON.stringify({
                mode: 'and',
                filters: [{
                  key: 'fromId',
                  values: [context_data.entity_id],
                }],
                filterGroups: [],
              })
              : '';
            redirectURI = `/dashboard/pirs/${pir.id}/threats/?filters=${encodeURIComponent(addInPirFilters)}`;
          }

          const content = (
            <MarkdownDisplay
              commonmark
              remarkGfmPlugin
              content={historyMessage}
            />
          );

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
                  alignItems: 'flex-start',
                }}
              >
                <Tooltip title={t_i18n(displayEntityTypeForTranslation(context_data?.entity_type ?? ''))}>
                  <div>
                    <ItemIcon size="large" type={context_data?.entity_type} />
                  </div>
                </Tooltip>
                <div>
                  <Typography
                    sx={{ marginTop: 0.5, marginBottom: 0 }}
                    variant="h3"
                  >
                    {context_data?.entity_name}
                  </Typography>
                  <Typography
                    color={theme.palette.text?.secondary}
                    sx={{ marginBottom: 1 }}
                    variant="body2"
                  >
                    {nsdt(timestamp)}
                  </Typography>
                  <div style={{ display: 'flex', gap: theme.spacing(2) }}>
                    <Avatar
                      sx={{
                        width: 24,
                        height: 24,
                        backgroundColor: 'transparent',
                        border: `1px solid ${color}`,
                        color: theme.palette.text?.primary,
                      }}
                    >
                      <div>{icon}</div>
                    </Avatar>
                    <Tooltip title={content}>{content}</Tooltip>
                  </div>
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
