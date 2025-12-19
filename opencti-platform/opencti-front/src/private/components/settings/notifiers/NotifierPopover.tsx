import React, { useState } from 'react';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import IconButton from '@common/button/IconButton';
import MoreVert from '@mui/icons-material/MoreVert';
import { graphql, useQueryLoader } from 'react-relay';
import Drawer from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import { deleteNode } from '../../../../utils/store';
import { NotifierLine_node$data } from './__generated__/NotifierLine_node.graphql';
import { NotifiersLinesPaginationQuery$variables } from './__generated__/NotifiersLinesPaginationQuery.graphql';
import NotifierEdition, { notifierEditionQuery } from './NotifierEdition';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { NotifierEditionQuery } from './__generated__/NotifierEditionQuery.graphql';
import DeleteDialog from '../../../../components/DeleteDialog';
import useDeletion from '../../../../utils/hooks/useDeletion';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

export const notifierPopoverDeletionMutation = graphql`
  mutation NotifierPopoverDeletionMutation($id: ID!) {
    notifierDelete(id: $id)
  }
`;

const NotifierPopover = ({ data, paginationOptions }: { data: NotifierLine_node$data; paginationOptions?: NotifiersLinesPaginationQuery$variables }) => {
  const { t_i18n } = useFormatter();
  const [queryRef, loadQuery] = useQueryLoader<NotifierEditionQuery>(notifierEditionQuery);
  const [anchorEl, setAnchorEl] = useState<HTMLElement | null>(null);
  const [displayEdit, setDisplayEdit] = useState<boolean>(false);
  const [commit] = useApiMutation(notifierPopoverDeletionMutation);
  //  popover
  const handleOpen = (event: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(event.currentTarget);
  };
  const handleClose = () => setAnchorEl(null);
  // delete
  const deletion = useDeletion({ handleClose });
  const { setDeleting, handleCloseDelete, handleOpenDelete } = deletion;
  const submitDelete = () => {
    commit({
      variables: {
        id: data.id,
      },
      updater: (store) => {
        deleteNode(store, 'Pagination_notifiers', paginationOptions, data.id);
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
  // Loader
  return (
    <>
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
        message={t_i18n('Do you want to delete this notifier?')}
      />
      <Drawer
        title={t_i18n('Notifier edition')}
        open={displayEdit}
        onClose={() => setDisplayEdit(false)}
      >
        {queryRef && (
          <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
            <NotifierEdition queryRef={queryRef} onClose={() => setDisplayEdit(false)} />
          </React.Suspense>
        )}
      </Drawer>
    </>
  );
};

export default NotifierPopover;
