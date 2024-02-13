import React from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { WorkspaceShareListQuery } from '@components/workspaces/__generated__/WorkspaceShareListQuery.graphql';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import ToggleButton from '@mui/material/ToggleButton';
import Tooltip from '@mui/material/Tooltip';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import { useTheme } from '@mui/styles';
import DeleteIcon from '@mui/icons-material/Delete';
import { useFormatter } from '../../../components/i18n';
import type { Theme } from '../../../components/Theme';
import { copyToClipboard } from '../../../utils/utils';
import ItemMarkings from '../../../components/ItemMarkings';

export const workspaceShareListQuery = graphql`
  query WorkspaceShareListQuery($filters: FilterGroup) {
    publicDashboards(filters: $filters) {
      edges {
        node {
          id
          uri_key
          name
          user_id
          created_at
          updated_at
          allowed_markings {
            id
            definition
            x_opencti_color
          }
        }
      }
    }
  }
`;

interface WorkspaceShareListProps {
  queryRef: PreloadedQuery<WorkspaceShareListQuery>
  onDelete: (id: string) => void
}

const WorkspaceShareList = ({ queryRef, onDelete }: WorkspaceShareListProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n, fld } = useFormatter();
  const { publicDashboards } = usePreloadedQuery(workspaceShareListQuery, queryRef);
  const dashboards = publicDashboards?.edges
    .map((edge) => edge.node)
    .sort((a, b) => a.created_at.localeCompare(b.created_at));

  const copyLinkUrl = (uriKey: string) => {
    copyToClipboard(
      t_i18n,
      `${window.location.origin}/public/dashboard/${uriKey}`,
    );
  };

  if (!dashboards || dashboards.length === 0) {
    return <p>{t_i18n('No public dashboard created yet')}</p>;
  }

  return (
    <div style={{ marginTop: '12px', display: 'flex', gap: '12px', flexDirection: 'column' }}>
      {dashboards.map((dashboard) => (
        <Paper
          key={dashboard.uri_key}
          variant="outlined"
          sx={{ padding: '12px' }}
        >
          <div style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'start',
            marginBottom: '8px',
          }}
          >
            <div>
              <Typography variant="body1">
                {dashboard.name}
              </Typography>
              <Typography variant="body2">
                public/dashboard/{dashboard.uri_key}
              </Typography>
            </div>

            <ToggleButtonGroup size="small">
              <Tooltip title={t_i18n('Copy link')}>
                <ToggleButton
                  aria-label="Label"
                  size="small"
                  value="copy-link"
                  onClick={() => copyLinkUrl(dashboard.uri_key)}
                >
                  <ContentCopyIcon fontSize="small" color="primary" />
                </ToggleButton>
              </Tooltip>
              {/* <Tooltip title={t_i18n('Disable public dashboard')}> */}
              {/*  <ToggleButton */}
              {/*    aria-label="Label" */}
              {/*    size="small" */}
              {/*    value="disable-link" */}
              {/*  > */}
              {/*    <DoNotDisturbAltIcon fontSize="small" color="primary" /> */}
              {/*  </ToggleButton> */}
              {/* </Tooltip> */}
              <Tooltip title={t_i18n('Delete public dashboard')}>
                <ToggleButton
                  aria-label="Label"
                  size="small"
                  value="delete-link"
                  onClick={() => onDelete(dashboard.id)}
                >
                  <DeleteIcon fontSize="small" color="primary" />
                </ToggleButton>
              </Tooltip>
            </ToggleButtonGroup>
          </div>

          <div
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'end',
            }}
          >
            <ItemMarkings
              variant="inList"
              markingDefinitions={dashboard.allowed_markings ?? []}
            />
            <Typography variant="body2" sx={{ color: theme.palette.text?.secondary }}>
              {t_i18n('Link created')} {fld(dashboard.created_at)}
            </Typography>
          </div>
        </Paper>
      ))}
    </div>
  );
};

export default WorkspaceShareList;
