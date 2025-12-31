import React, { FunctionComponent, useState } from 'react';
import IconButton from '@common/button/IconButton';
import MoreVert from '@mui/icons-material/MoreVert';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import { graphql } from 'react-relay';
import { DisseminationListsLine_node$data } from '@components/settings/dissemination_lists/__generated__/DisseminationListsLine_node.graphql';
import { DisseminationListsLinesPaginationQuery$variables } from '@components/settings/dissemination_lists/__generated__/DisseminationListsLinesPaginationQuery.graphql';
import DisseminationListEdition from '@components/settings/dissemination_lists/DisseminationListEdition';
import { handleError } from 'src/relay/environment';
import DeleteDialog from '../../../../components/DeleteDialog';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useDeletion from '../../../../utils/hooks/useDeletion';
import { deleteNode } from '../../../../utils/store';

export const disseminationListPopoverDeletionMutation = graphql`
  mutation DisseminationListPopoverDeletionMutation($id: ID!) {
    disseminationListDelete(id: $id)
  }
`;

interface DisseminationListPopoverProps {
  data: DisseminationListsLine_node$data;
  paginationOptions?: DisseminationListsLinesPaginationQuery$variables;
}

const DisseminationListPopover: FunctionComponent<DisseminationListPopoverProps> = ({
  data,
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();

  const [anchorEl, setAnchorEl] = useState<HTMLElement | null>(null);
  const [isEditionFormOpen, setIsEditionFormOpen] = useState<boolean>(false);

  const [commit] = useApiMutation(disseminationListPopoverDeletionMutation);

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
        deleteNode(store, 'Pagination_disseminationLists', paginationOptions, data.id);
      },
      onCompleted: () => {
        setDeleting(false);
        handleCloseDelete();
      },
      onError: (error: Error) => {
        handleError(error);
        handleCloseDelete();
      },
    });
  };

  // edition
  const handleDisplayEdit = () => {
    setIsEditionFormOpen(true);
    handleClose();
  };

  const handleCloseEditionForm = () => setIsEditionFormOpen(false);

  return (
    <>
      <IconButton
        onClick={handleOpen}
        aria-haspopup="true"
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
        message={t_i18n('Do you want to delete this dissemination list?')}
      />
      <DisseminationListEdition
        data={data}
        isOpen={isEditionFormOpen}
        onClose={handleCloseEditionForm}
      />
    </>
  );
};

export default DisseminationListPopover;
