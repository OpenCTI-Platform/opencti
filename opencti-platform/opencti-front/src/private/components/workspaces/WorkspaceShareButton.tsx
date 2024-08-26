import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import ToggleButton from '@mui/material/ToggleButton';
import ShareIcon from '@mui/icons-material/Share';
import Tooltip from '@mui/material/Tooltip';
import React, { Suspense, useEffect, useRef, useState } from 'react';
import Drawer from '@components/common/drawer/Drawer';
import Typography from '@mui/material/Typography';
import PublicDashboardCreationForm from '@components/workspaces/dashboards/public_dashboards/PublicDashboardCreationForm';
import WorkspaceShareList, { workspaceShareListQuery } from '@components/workspaces/WorkspaceShareList';
import { WorkspaceShareListQuery } from '@components/workspaces/__generated__/WorkspaceShareListQuery.graphql';
import { graphql, useQueryLoader } from 'react-relay';
import Alert from '@mui/material/Alert';
import { useFormatter } from '../../../components/i18n';
import Loader, { LoaderVariant } from '../../../components/Loader';
import DeleteDialog from '../../../components/DeleteDialog';
import useDeletion from '../../../utils/hooks/useDeletion';
import useApiMutation from '../../../utils/hooks/useApiMutation';

const workspaceShareButtonDeleteMutation = graphql`
  mutation WorkspaceShareButtonDeleteMutation($id: ID!) {
    publicDashboardDelete(id: $id)
  }
`;

const workspaceShareButtonEditMutation = graphql`
  mutation WorkspaceShareButtonEditMutation($id: ID!, $input: [EditInput!]!) {
    publicDashboardFieldPatch(id: $id, input: $input) {
      id
      uri_key
      enabled
    }
  }
`;

interface WorkspaceShareButtonProps {
  workspaceId: string
}

const WorkspaceShareButton = ({ workspaceId }: WorkspaceShareButtonProps) => {
  const { t_i18n } = useFormatter();

  const idToDelete = useRef<string>();
  const deletion = useDeletion({});

  const [drawerOpen, setDrawerOpen] = useState(false);
  const [commitDeleteMutation] = useApiMutation(workspaceShareButtonDeleteMutation);
  const [commitEditMutation] = useApiMutation(workspaceShareButtonEditMutation);

  const [publicDashboardsQueryRef, fetchPublicDashboards] = useQueryLoader<WorkspaceShareListQuery>(workspaceShareListQuery);
  const fetchPublicDashboardsWithFilters = () => {
    fetchPublicDashboards(
      {
        filters: {
          mode: 'and',
          filterGroups: [],
          filters: [{
            key: ['dashboard_id'],
            values: [workspaceId],
          }],
        },
      },
      { fetchPolicy: 'store-and-network' },
    );
  };

  useEffect(() => {
    fetchPublicDashboardsWithFilters();
  }, []);

  const confirmDelete = (id: string) => {
    idToDelete.current = id;
    deletion.handleOpenDelete();
  };

  const onDelete = () => {
    if (idToDelete.current) {
      deletion.setDeleting(true);
      commitDeleteMutation({
        variables: {
          id: idToDelete.current,
        },
        onCompleted: () => {
          deletion.setDeleting(false);
          deletion.handleCloseDelete();
          idToDelete.current = undefined;
          fetchPublicDashboardsWithFilters();
        },
      });
    }
  };

  const onToggleEnabled = (dashboardId: string, enabled: boolean) => {
    commitEditMutation({
      variables: {
        id: dashboardId,
        input: [{
          key: 'enabled',
          value: [enabled],
        }],
      },
      onCompleted: () => {
        fetchPublicDashboardsWithFilters();
      },
    });
  };

  return (
    <>
      <Tooltip title={t_i18n('Share as public dashboard')}>
        <ToggleButtonGroup size="small">
          <ToggleButton
            aria-label="Label"
            size="small"
            value="share-dashboard"
            onClick={() => setDrawerOpen(true)}
          >
            <ShareIcon fontSize="small" color="primary" />
          </ToggleButton>
        </ToggleButtonGroup>
      </Tooltip>

      <Drawer
        title={t_i18n('Public dashboards')}
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
      >
        <div
          style={{
            display: 'flex',
            flexDirection: 'column',
            paddingTop: '20px',
            gap: '20px',
          }}
        >
          <section>
            <Typography
              variant="h4"
              gutterBottom={true}
            >
              {t_i18n('Create a new public dashboard')}
            </Typography>

            <PublicDashboardCreationForm
              dashboard_id={workspaceId}
              onCompleted={fetchPublicDashboardsWithFilters}
            />
          </section>

          <section>
            <Typography
              variant="h4"
              gutterBottom={true}
              sx={{ marginBottom: '12px' }}
            >
              {t_i18n('Existing public dashboards')}
            </Typography>

            <Alert severity="info" variant="outlined">
              {t_i18n('A public dashboard is a snapshot...')}
            </Alert>

            {publicDashboardsQueryRef && (
              <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
                <WorkspaceShareList
                  queryRef={publicDashboardsQueryRef}
                  onDelete={confirmDelete}
                  onToggleEnabled={onToggleEnabled}
                />
              </Suspense>
            )}
          </section>
        </div>
      </Drawer>

      <DeleteDialog
        title={t_i18n('Are you sure you want to delete this public dashboard?')}
        deletion={deletion}
        submitDelete={onDelete}
      />
    </>
  );
};

export default WorkspaceShareButton;
