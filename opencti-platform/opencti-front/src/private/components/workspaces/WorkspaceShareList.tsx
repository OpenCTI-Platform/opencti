import React from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { WorkspaceShareListQuery } from '@components/workspaces/__generated__/WorkspaceShareListQuery.graphql';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import ToggleButton from '@mui/material/ToggleButton';
import Tooltip from '@mui/material/Tooltip';
import { ContentCopy, Delete, DoNotDisturbAlt, Done, ReportGmailerrorred } from '@mui/icons-material';
import { useTheme } from '@mui/styles';
import { useFormatter } from '../../../components/i18n';
import type { Theme } from '../../../components/Theme';
import { copyToClipboard } from '../../../utils/utils';
import ItemMarkings from '../../../components/ItemMarkings';
import ItemBoolean from '../../../components/ItemBoolean';
import useAuth from '../../../utils/hooks/useAuth';

export const workspaceShareListQuery = graphql`
  query WorkspaceShareListQuery($filters: FilterGroup) {
    publicDashboards(filters: $filters) {
      edges {
        node {
          id
          uri_key
          enabled
          name
          user_id
          created_at
          updated_at
          allowed_markings {
            id
            definition
            definition_type
            x_opencti_color
            x_opencti_order
          }
        }
      }
    }
  }
`;

interface WorkspaceShareListProps {
  queryRef: PreloadedQuery<WorkspaceShareListQuery>
  onDelete: (id: string) => void
  onToggleEnabled: (id: string, enabled: boolean) => void
}

const WorkspaceShareList = ({ queryRef, onDelete, onToggleEnabled }: WorkspaceShareListProps) => {
  const { me } = useAuth();

  const theme = useTheme<Theme>();
  const { t_i18n, fld } = useFormatter();

  const { publicDashboards } = usePreloadedQuery(workspaceShareListQuery, queryRef);
  const dashboards = publicDashboards?.edges
    .map((edge) => edge.node)
    .sort((a, b) => a.created_at.localeCompare(b.created_at));

  const copyLinkUrl = (uriKey: string) => {
    copyToClipboard(
      t_i18n,
      `${window.location.origin}/public/dashboard/${uriKey.toLowerCase()}`,
    );
  };

  if (!dashboards || dashboards.length === 0) {
    return <p>{t_i18n('No public dashboard created yet')}</p>;
  }

  const filterMaxMarkings = (dashboard: typeof dashboards[0]) => {
    const { allowed_markings } = dashboard;
    return (me.max_shareable_marking ?? []).filter((maxMarking) => {
      const marking = (allowed_markings ?? []).find((m) => m.definition_type === maxMarking.definition_type);
      return marking && marking.x_opencti_order > maxMarking.x_opencti_order;
    });
  };

  return (
    <div style={{ marginTop: '12px', display: 'flex', gap: '12px', flexDirection: 'column' }}>
      {dashboards.map((dashboard) => {
        const maxMarkings = filterMaxMarkings(dashboard);
        return (
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

              <div style={{ display: 'flex', alignItems: 'center' }}>
                <ItemBoolean
                  status={dashboard.enabled}
                  label={dashboard.enabled ? t_i18n('Enabled') : t_i18n('Disabled')}
                />

                <ToggleButtonGroup size="small">
                  <Tooltip title={t_i18n('Copy link')}>
                    <ToggleButton
                      aria-label="Label"
                      size="small"
                      value="copy-link"
                      onClick={() => copyLinkUrl(dashboard.uri_key)}
                    >
                      <ContentCopy fontSize="small" color="primary" />
                    </ToggleButton>
                  </Tooltip>
                  <Tooltip title={dashboard.enabled ? t_i18n('Disable public dashboard') : t_i18n('Enable public dashboard')}>
                    <ToggleButton
                      aria-label="Label"
                      size="small"
                      value="disable-link"
                      onClick={() => onToggleEnabled(dashboard.id, !dashboard.enabled)}
                    >
                      {dashboard.enabled && <DoNotDisturbAlt fontSize="small" color="primary" />}
                      {!dashboard.enabled && <Done fontSize="small" color="primary" />}
                    </ToggleButton>
                  </Tooltip>
                  <Tooltip title={t_i18n('Delete public dashboard')}>
                    <ToggleButton
                      aria-label="Label"
                      size="small"
                      value="delete-link"
                      onClick={() => onDelete(dashboard.id)}
                    >
                      <Delete fontSize="small" color="primary" />
                    </ToggleButton>
                  </Tooltip>
                </ToggleButtonGroup>
              </div>
            </div>

            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'end',
              }}
            >
              <div>
                <ItemMarkings
                  variant="inList"
                  markingDefinitions={dashboard.allowed_markings ?? []}
                />
                {maxMarkings.length > 0 && (
                  <Tooltip
                    title={(
                      <div style={{ display: 'flex', flexFlow: 'column', padding: '4px', gap: '4px' }}>
                        <div>{t_i18n('Max marking definitions override...')}</div>
                        <div>
                          <ItemMarkings
                            variant="inList"
                            markingDefinitions={maxMarkings}
                          />
                        </div>
                      </div>
                    )}
                  >
                    <ReportGmailerrorred fontSize={'small'} color={'error'} />
                  </Tooltip>
                )}
              </div>
              <Typography variant="body2" sx={{ color: theme.palette.text?.secondary }}>
                {t_i18n('Public dashboard created the')} {fld(dashboard.created_at)}
              </Typography>
            </div>
          </Paper>
        );
      })}
    </div>
  );
};

export default WorkspaceShareList;
