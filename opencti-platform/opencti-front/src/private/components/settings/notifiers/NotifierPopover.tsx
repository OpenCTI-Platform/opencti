import React, { useState } from 'react';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import IconButton from '@mui/material/IconButton';
import MoreVert from '@mui/icons-material/MoreVert';
import { graphql, useMutation, useQueryLoader } from 'react-relay';
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

export const notifierPopoverDeletionMutation = graphql`
  mutation NotifierPopoverDeletionMutation($id: ID!) {
    notifierDelete(id: $id)
  }
`;

const NotifierPopover = ({ data, paginationOptions }: { data: NotifierLine_node$data, paginationOptions?: NotifiersLinesPaginationQuery$variables }) => {
  const { t } = useFormatter();
  const [queryRef, loadQuery] = useQueryLoader<NotifierEditionQuery>(notifierEditionQuery);
  const [anchorEl, setAnchorEl] = useState<HTMLElement | null>(null);
  const [displayEdit, setDisplayEdit] = useState<boolean>(false);
  const [commit] = useMutation(notifierPopoverDeletionMutation);
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
    <div>
      <IconButton
        onClick={handleOpen}
        aria-haspopup="true"
        style={{ marginTop: 3 }}
        size="large">
        <MoreVert />
      </IconButton>
      <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleClose}>
        <MenuItem onClick={handleDisplayEdit}>{t('Update')}</MenuItem>
        <MenuItem onClick={handleOpenDelete}>{t('Delete')}</MenuItem>
      </Menu>
      <DeleteDialog
        title={t('Do you want to delete this notifier?')}
        deletion={deletion}
        submitDelete={submitDelete}
      />
      <Drawer
        title={t('Notifier edition')}
        open={displayEdit}
        onClose={() => setDisplayEdit(false)}
      >
        {queryRef && (
          <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
            <NotifierEdition queryRef={queryRef} onClose={() => setDisplayEdit(false)} />
          </React.Suspense>
        )}
      </Drawer>
    </div>
  );
};

export default NotifierPopover;
