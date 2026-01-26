import IconButton from '@common/button/IconButton';
import MoreVert from '@mui/icons-material/MoreVert';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import React, { useState } from 'react';
import { graphql, useQueryLoader } from 'react-relay';
import DeleteDialog from '../../../../../components/DeleteDialog';
import { useFormatter } from '../../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../../components/Loader';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import useDeletion from '../../../../../utils/hooks/useDeletion';
import { deleteNode } from '../../../../../utils/store';
import Drawer from '../../../common/drawer/Drawer';
import { AlertEditionQuery } from './__generated__/AlertEditionQuery.graphql';
import { AlertingLine_node$data } from './__generated__/AlertingLine_node.graphql';
import { AlertingPaginationQuery$variables } from './__generated__/AlertingPaginationQuery.graphql';
import AlertDigestEdition from './AlertDigestEdition';
import { alertEditionQuery } from './AlertEditionQuery';
import AlertLiveEdition from './AlertLiveEdition';

export const alertingPopoverDeletionMutation = graphql`
  mutation AlertingPopoverDeletionMutation($id: ID!) {
    triggerActivityDelete(id: $id)
  }
`;

const AlertingPopover = ({ data, paginationOptions }: { data: AlertingLine_node$data; paginationOptions?: AlertingPaginationQuery$variables }) => {
  const { t_i18n } = useFormatter();
  const [queryRef, loadQuery] = useQueryLoader<AlertEditionQuery>(alertEditionQuery);
  const isLiveEdition = data.trigger_type === 'live';
  const isDigestEdition = data.trigger_type === 'digest';
  const [anchorEl, setAnchorEl] = useState<HTMLElement | null>(null);
  const [displayEdit, setDisplayEdit] = useState<boolean>(false);
  const [commit] = useApiMutation(alertingPopoverDeletionMutation);
  //  popover
  const handleOpen = (event: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(event.currentTarget);
  };
  const handleClose = () => setAnchorEl(null);
  const deletion = useDeletion({ handleClose });
  const { setDeleting, handleOpenDelete, handleCloseDelete } = deletion;
  const submitDelete = () => {
    setDeleting(true);
    commit({
      variables: {
        id: data.id,
      },
      updater: (store) => {
        deleteNode(store, 'Pagination_triggersActivity', paginationOptions, data.id);
      },
      onCompleted: () => {
        setDeleting(false);
        handleCloseDelete();
      },
    });
  };
  // edition
  const handleDisplayEdit = () => {
    loadQuery({ id: data.id }, { fetchPolicy: 'store-and-network' });
    setDisplayEdit(true);
    handleClose();
  };

  let title = '';
  if (isLiveEdition) {
    title = t_i18n('Update an activity live trigger');
  }
  if (isDigestEdition) {
    title = t_i18n('Update an activity digest trigger');
  }
  // Loader
  return (
    <div style={{ marginRight: 25 }}>
      <IconButton
        onClick={handleOpen}
        aria-haspopup="true"
        style={{ marginTop: 3 }}
        color="primary"
      >
        <MoreVert />
      </IconButton>
      <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleClose}>
        <MenuItem onClick={handleDisplayEdit}>{t_i18n('Update')}</MenuItem>
        <MenuItem onClick={handleOpenDelete}>{t_i18n('Delete')}</MenuItem>
      </Menu>
      <DeleteDialog
        deletion={deletion}
        submitDelete={submitDelete}
        message={t_i18n('Do you want to delete this trigger?')}
      />
      {displayEdit && (
        <Drawer
          open={true}
          title={title}
          onClose={() => setDisplayEdit(false)}
        >
          {queryRef && (
            <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
              {isLiveEdition && <AlertLiveEdition queryRef={queryRef} paginationOptions={paginationOptions} handleClose={() => setDisplayEdit(false)} />}
              {isDigestEdition && <AlertDigestEdition queryRef={queryRef} paginationOptions={paginationOptions} handleClose={() => setDisplayEdit(false)} />}
            </React.Suspense>
          )}
        </Drawer>
      )}
    </div>
  );
};

export default AlertingPopover;
