import React, { useState } from 'react';
import IconButton from '@mui/material/IconButton';
import MoreVert from '@mui/icons-material/MoreVert';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import DeleteDialog from '../../../../components/DeleteDialog';
import Drawer from '@components/common/drawer/Drawer';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';
import { graphql } from 'react-relay';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useDeletion from '../../../../utils/hooks/useDeletion';
import { deleteNode } from '../../../../utils/store';
import { ExclusionListsLine_node$data } from '@components/settings/exclusion_lists/__generated__/ExclusionListsLine_node.graphql';
import { ExclusionListsLinesPaginationQuery$variables } from '@components/settings/exclusion_lists/__generated__/ExclusionListsLinesPaginationQuery.graphql';

export const exclusionListPopoverDeletionMutation = graphql`
  mutation ExclusionListPopoverDeletionMutation($id: ID!) {
    exclusionListDelete(id: $id)
  }
`;

const ExclusionListPopover = ({ data, paginationOptions }: { data: ExclusionListsLine_node$data, paginationOptions?: ExclusionListsLinesPaginationQuery$variables }) => {
  const { t_i18n } = useFormatter();
  // const [queryRef, loadQuery] = useQueryLoader<ExclusionListEditionQuery>(exclusionListEditionQuery);
  const [anchorEl, setAnchorEl] = useState<HTMLElement | null>(null);
  const [displayEdit, setDisplayEdit] = useState<boolean>(false);
  const [commit] = useApiMutation(exclusionListPopoverDeletionMutation);

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
        deleteNode(store, 'Pagination_exclusionLists', paginationOptions, data.id);
      },
      onCompleted: () => {
        setDeleting(false);
        handleCloseDelete();
      },
    });
  };

  // edition
  const handleDisplayEdit = () => {
    // loadQuery({ id: data.id }, { fetchPolicy: 'store-and-network' });
    setDisplayEdit(true);
    handleClose();
  };

  // Enable - Disable
  const handleEnable = () => {
    // TODO : update the status
    handleClose();
  };
  return (
    <>
      <IconButton
        onClick={handleOpen}
        aria-haspopup="true"
        style={{ marginTop: 3 }}
        size="large"
        color="primary"
      >
        <MoreVert />
      </IconButton>
      <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleClose}>
        <MenuItem onClick={handleEnable} disabled>{t_i18n('Enable')}</MenuItem>
        <MenuItem onClick={handleDisplayEdit}>{t_i18n('Update')}</MenuItem>
        <MenuItem onClick={handleOpenDelete} disabled>{t_i18n('Delete')}</MenuItem>
      </Menu>
      <DeleteDialog
        title={t_i18n('Do you want to delete this exclusion list?')}
        deletion={deletion}
        submitDelete={submitDelete}
      />
      <Drawer
        title={t_i18n('Exclusion list edition')}
        open={displayEdit}
        onClose={() => setDisplayEdit(false)}
      >
        <div>TODO</div>
        {/*{queryRef && (*/}
        {/*  <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>*/}
        {/*    <ExclusionListEdition queryRef={queryRef} onClose={() => setDisplayEdit(false)} />*/}
        {/*  </React.Suspense>*/}
        {/*/!*)}*!/*/}
      </Drawer>
    </>
  );
};

export default ExclusionListPopover;
