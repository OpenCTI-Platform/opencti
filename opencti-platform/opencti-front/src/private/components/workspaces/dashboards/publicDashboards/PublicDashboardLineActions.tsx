import { PublicDashboards_PublicDashboard$data } from '@components/workspaces/dashboards/publicDashboards/__generated__/PublicDashboards_PublicDashboard.graphql';
import MoreVert from '@mui/icons-material/MoreVert';
import { IconButton, Menu, MenuItem, MenuProps } from '@mui/material';
import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { graphql } from 'react-relay';
import { useFormatter } from '../../../../../components/i18n';
import { copyToClipboard } from '../../../../../utils/utils';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import useDeletion from '../../../../../utils/hooks/useDeletion';
import DeleteDialog from '../../../../../components/DeleteDialog';

interface PublicDashboardLineActionsProps {
  publicDashboard: PublicDashboards_PublicDashboard$data
}

const publicDashboardLineActionsDeleteMutation = graphql`
  mutation PublicDashboardLineActionsDeleteMutation($id: ID!){
    publicDashboardDelete(id: $id)
  }`;

const publicDashboardLineActionsEditMutation = graphql`
  mutation PublicDashboardLineActionsEditMutation($id: ID!, $input: [EditInput!]!) {
    publicDashboardFieldPatch(id: $id, input: $input) {
      id
      uri_key
      enabled
    }
  }
`;

const PublicDashboardLineActions = ({ publicDashboard }: PublicDashboardLineActionsProps) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const [anchor, setAnchor] = useState<MenuProps['anchorEl']>();
  const [commitEditMutation] = useApiMutation(publicDashboardLineActionsEditMutation);
  const [commitDeleteMutation] = useApiMutation(publicDashboardLineActionsDeleteMutation);
  const deletion = useDeletion({});
  const { handleOpenDelete } = deletion;
  console.log('DASHBOARD', publicDashboard);
  const copyLinkUrl = () => {
    copyToClipboard(
      t_i18n,
      `${window.location.origin}/public/dashboard/${publicDashboard.uri_key.toLowerCase()}`,
    );
  };

  const goToDashboard = () => {
    navigate(`/dashboard/workspaces/dashboards/${publicDashboard.dashboard?.id}`);
  };

  const onDelete = () => {
    if (publicDashboard.id) {
      deletion.setDeleting(true);
      commitDeleteMutation({
        variables: {
          id: publicDashboard.id,
        },
        onCompleted: () => {
          deletion.setDeleting(false);
          deletion.handleCloseDelete();
        },
      });
    }
  };
  const onToggleEnabled = () => {
    commitEditMutation({
      variables: {
        id: publicDashboard.id,
        input: [{ key: 'enabled', value: [!publicDashboard.enabled] }],
      },
    });
  };

  return (
    <>
      <IconButton
        onClick={(event) => setAnchor(event.currentTarget)}
        color="primary"
      >
        <MoreVert/>
      </IconButton>

      <Menu
        key={publicDashboard.uri_key}
        anchorEl={anchor}
        open={!!anchor}
        onClose={() => setAnchor(undefined)}
      >
        <MenuItem
          onClick={() => goToDashboard()}
          aria-label="Go to dashboard"
        >
          {t_i18n('Go to Original dashboard')}
        </MenuItem>
        <MenuItem
          onClick={() => copyLinkUrl()}
          aria-label="Copy link"
        >
          {t_i18n('Copy public link')}
        </MenuItem>
        <MenuItem
          onClick={() => onToggleEnabled()}
          aria-label="Disable link"
        >
          {publicDashboard.enabled
            ? t_i18n('Disable public link')
            : t_i18n('Enable public dashboard')}
        </MenuItem>
        <MenuItem
          onClick={() => handleOpenDelete()}
          aria-label="Delete"
        >
          {t_i18n('Delete')}
        </MenuItem>

      </Menu>
      <DeleteDialog
        title={t_i18n('Are you sure you want to delete this public dashboard?')}
        deletion={deletion}
        submitDelete={onDelete}
      />
    </>
  );
};

export default PublicDashboardLineActions;
