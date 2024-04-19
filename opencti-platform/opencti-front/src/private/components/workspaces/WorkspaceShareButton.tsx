import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import ToggleButton from '@mui/material/ToggleButton';
import ShareIcon from '@mui/icons-material/Share';
import Tooltip from '@mui/material/Tooltip';
import React, { Suspense, useEffect, useRef, useState } from 'react';
import Drawer from '@components/common/drawer/Drawer';
import Typography from '@mui/material/Typography';
import WorkspaceShareForm, { WorkspaceShareFormData } from '@components/workspaces/WorkspaceShareForm';
import WorkspaceShareList, { workspaceShareListQuery } from '@components/workspaces/WorkspaceShareList';
import { WorkspaceShareListQuery } from '@components/workspaces/__generated__/WorkspaceShareListQuery.graphql';
import { graphql, useQueryLoader, UseQueryLoaderLoadQueryOptions } from 'react-relay';
import { FormikConfig } from 'formik/dist/types';
import Alert from '@mui/material/Alert';
import { useFormatter } from '../../../components/i18n';
import Loader, { LoaderVariant } from '../../../components/Loader';
import DeleteDialog from '../../../components/DeleteDialog';
import useDeletion from '../../../utils/hooks/useDeletion';
import { handleError } from '../../../relay/environment';
import useApiMutation from '../../../utils/hooks/useApiMutation';

const workspaceShareButtonCreateMutation = graphql`
  mutation WorkspaceShareButtonCreateMutation($input: PublicDashboardAddInput!) {
    publicDashboardAdd(input: $input) {
      id
      uri_key
    }
  }
`;

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
  const [commitCreateMutation] = useApiMutation(workspaceShareButtonCreateMutation);
  const [commitDeleteMutation] = useApiMutation(workspaceShareButtonDeleteMutation);
  const [commitEditMutation] = useApiMutation(workspaceShareButtonEditMutation);

  const [publicDashboardsQueryRef, fetchList] = useQueryLoader<WorkspaceShareListQuery>(workspaceShareListQuery);
  const fetchWithFilters = (options?: UseQueryLoaderLoadQueryOptions) => {
    fetchList(
      {
        filters: {
          mode: 'and',
          filterGroups: [],
          filters: [{
            key: ['dashboard_id'],
            mode: 'or',
            operator: 'eq',
            values: [workspaceId],
          }],
        },
      },
      options,
    );
  };

  useEffect(() => {
    fetchWithFilters({ fetchPolicy: 'store-and-network' });
  }, []);

  const onSubmit: FormikConfig<WorkspaceShareFormData>['onSubmit'] = (values, { setSubmitting, resetForm }) => {
    commitCreateMutation({
      variables: {
        input: {
          name: values.name,
          enabled: values.enabled,
          uri_key: values.uri_key,
          dashboard_id: workspaceId,
          allowed_markings_ids: values.max_markings.map((marking) => marking.value),
        },
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        fetchWithFilters({ fetchPolicy: 'store-and-network' });
      },
      onError: (error) => {
        setSubmitting(false);
        handleError(error);
      },
    });
  };

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
          fetchWithFilters({ fetchPolicy: 'store-and-network' });
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
        fetchWithFilters({ fetchPolicy: 'store-and-network' });
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

            <WorkspaceShareForm onSubmit={onSubmit} />
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
