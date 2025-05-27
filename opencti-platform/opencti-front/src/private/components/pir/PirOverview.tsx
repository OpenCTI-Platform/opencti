import { graphql, useFragment } from 'react-relay';
import React from 'react';
import Paper from '@mui/material/Paper';
import Tooltip from '@mui/material/Tooltip';
import { deepOrange, green, indigo, pink, red, teal, yellow } from '@mui/material/colors';
import { AddOutlined, DeleteOutlined, EditOutlined, HelpOutlined } from '@mui/icons-material';
import { LinkVariantPlus, LinkVariantRemove, Merge } from 'mdi-material-ui';
import Avatar from '@mui/material/Avatar';
import Badge from '@mui/material/Badge';
import { useTheme } from '@mui/material/styles';
import { PirOverviewHistoryFragment$key } from './__generated__/PirOverviewHistoryFragment.graphql';
import MarkdownDisplay from '../../../components/MarkdownDisplay';
import type { Theme } from '../../../components/Theme';
import { useFormatter } from '../../../components/i18n';
import { isNotEmptyField } from '../../../utils/utils';

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

interface PirOverviewProps {
  data: PirOverviewHistoryFragment$key
}

const HISTORY_ICON_CONFIG = {
  create: {
    color: pink[500],
    icon: <AddOutlined sx={{ fontSize: 15 }} />,
  },
  delete: {
    color: red[500],
    icon: <DeleteOutlined sx={{ fontSize: 15 }} />,
  },
  merge: {
    color: teal[500],
    icon: <Merge sx={{ fontSize: 15 }} />,
  },
  updateReplaces: {
    color: green[500],
    icon: <EditOutlined sx={{ fontSize: 15 }} />,
  },
  updateChanges: {
    color: green[500],
    icon: <EditOutlined sx={{ fontSize: 15 }} />,
  },
  updateAdds: {
    color: indigo[500],
    icon: <LinkVariantPlus sx={{ fontSize: 15 }} />,
  },
  updateRemoves: {
    color: deepOrange[500],
    icon: <LinkVariantRemove sx={{ fontSize: 15 }} />,
  },
  default: {
    color: yellow[500],
    icon: <HelpOutlined sx={{ fontSize: 15 }} />,
  },
};

const PirOverview = ({ data }: PirOverviewProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n, nsdt } = useFormatter();

  const { logs } = useFragment(pirHistoryFragment, data);
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

  return (
    <Paper
      sx={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(2), padding: 2 }}
      variant="outlined"
    >
      {history.map((historyItem) => {
        const { id, user, context_data, timestamp, entity_type, event_scope } = historyItem;
        const { color, icon } = getIconConfig(historyItem);
        const isHistoryUpdate = entity_type === 'History'
          && event_scope === 'update'
          && isNotEmptyField(context_data?.entity_name);
        const historyMessage = `\`${user?.name}\` ${context_data?.message} ${
          isHistoryUpdate
            ? `for \`${context_data?.entity_name}\` (${context_data?.entity_type ? t_i18n(context_data.entity_type.toString()[0] === context_data.entity_type.toString()[0].toUpperCase()
              ? `entity_${context_data.entity_type.toString()}`
              : `relationship_${context_data.entity_type.toString()}`) : undefined})` // TODO PIR use displayEntityTypeForTranslation after rebase on master
            : ''
        }`;
        const content = (
          <MarkdownDisplay
            content={historyMessage}
            remarkGfmPlugin={true}
            commonmark={true}
          />
        );
        return (
          <div
            style={{ display: 'flex', gap: theme.spacing(2), alignItems: 'center' }}
            key={id}
          >
            <Badge
              color="secondary"
              overlap="circular"
              badgeContent="M"
              invisible={context_data?.commit === null}
            >
              <Avatar
                sx={{
                  width: 25,
                  height: 25,
                  backgroundColor: 'transparent',
                  border: `1px solid ${color}`,
                  color: theme.palette.text?.primary,
                  cursor: context_data?.commit ? 'pointer' : 'auto',
                }}
              >
                {icon}
              </Avatar>
            </Badge>
            <Tooltip title={content}>
              <div style={{ flex: '1' }}>{content}</div>
            </Tooltip>
            <span style={{ fontSize: 11 }}>
              {nsdt(timestamp)}
            </span>
          </div>
        );
      })}
    </Paper>
  );
};

export default PirOverview;
