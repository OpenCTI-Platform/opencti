import React, { FunctionComponent, useState } from 'react';
import IconButton from '@common/button/IconButton';
import MoreVert from '@mui/icons-material/MoreVert';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import { graphql } from 'react-relay';
import { ExclusionListsLine_node$data } from '@components/settings/exclusion_lists/__generated__/ExclusionListsLine_node.graphql';
import { ExclusionListsLinesPaginationQuery$variables } from '@components/settings/exclusion_lists/__generated__/ExclusionListsLinesPaginationQuery.graphql';
import ExclusionListEdition, { exclusionListMutationFieldPatch } from '@components/settings/exclusion_lists/ExclusionListEdition';
import { Link } from 'react-router-dom';
import { APP_BASE_PATH } from 'src/relay/environment';
import DeleteDialog from '../../../../components/DeleteDialog';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useDeletion from '../../../../utils/hooks/useDeletion';
import { deleteNode } from '../../../../utils/store';

export const exclusionListPopoverDeletionMutation = graphql`
  mutation ExclusionListPopoverDeletionMutation($id: ID!) {
    exclusionListDelete(id: $id)
  }
`;

interface ExclusionListPopoverProps {
  data: ExclusionListsLine_node$data;
  paginationOptions?: ExclusionListsLinesPaginationQuery$variables;
  refetchStatus: () => void;
}

const ExclusionListPopover: FunctionComponent<ExclusionListPopoverProps> = ({
  data,
  paginationOptions,
  refetchStatus,
}) => {
  const { t_i18n } = useFormatter();

  const [anchorEl, setAnchorEl] = useState<HTMLElement | null>(null);
  const [isEditionFormOpen, setIsEditionFormOpen] = useState<boolean>(false);

  const [commit] = useApiMutation(exclusionListPopoverDeletionMutation);
  const [commitFieldPatch] = useApiMutation(exclusionListMutationFieldPatch);

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
        refetchStatus();
      },
    });
  };

  // edition
  const handleDisplayEdit = () => {
    setIsEditionFormOpen(true);
    handleClose();
  };

  // Enable - Disable
  const handleEnable = () => {
    commitFieldPatch({
      variables: {
        id: data.id,
        input: [{ key: 'enabled', value: !data.enabled }],
      },
      onCompleted: () => {
        refetchStatus();
      },
    });
    handleClose();
  };

  const handleCloseEditionForm = () => setIsEditionFormOpen(false);

  const downloadFileLink = `${APP_BASE_PATH}/storage/get/${encodeURIComponent(data.file_id)}`;

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
        <MenuItem onClick={handleEnable}>{data.enabled ? t_i18n('Disable') : t_i18n('Enable')}</MenuItem>
        <MenuItem onClick={handleDisplayEdit}>{t_i18n('Update')}</MenuItem>
        <MenuItem
          component={Link}
          to={downloadFileLink}
          onClick={handleClose}
          target="_blank"
          rel="noopener noreferrer"
        >{t_i18n('Download file')}
        </MenuItem>
        <MenuItem onClick={handleOpenDelete}>{t_i18n('Delete')}</MenuItem>
      </Menu>
      <DeleteDialog
        deletion={deletion}
        submitDelete={submitDelete}
        message={t_i18n('Do you want to delete this exclusion list?')}
      />
      {isEditionFormOpen && (
        <ExclusionListEdition
          data={data}
          isOpen={isEditionFormOpen}
          refetchStatus={refetchStatus}
          onClose={handleCloseEditionForm}
        />
      )}
    </>
  );
};

export default ExclusionListPopover;
