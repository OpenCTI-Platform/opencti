import React, { UIEvent, useState } from 'react';
import MoreVert from '@mui/icons-material/MoreVert';
import Button from '@mui/material/Button';
import { Menu, MenuItem, PopoverProps } from '@mui/material';
import { graphql } from 'react-relay';
import DeleteDialog from '../../../components/DeleteDialog';
import { useFormatter } from '../../../components/i18n';
import useDeletion from '../../../utils/hooks/useDeletion';
import stopEvent from '../../../utils/domEvent';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import { PirPopoverDeleteMutation } from './__generated__/PirPopoverDeleteMutation.graphql';

const pirDeleteMutation = graphql`
  mutation PirPopoverDeleteMutation($id: ID!) {
    pirDelete(id: $id)
  }
`;

interface PirPopoverProps {
  pirId: string
  onDeleteComplete?: () => void
}

const PirPopover = ({ pirId, onDeleteComplete }: PirPopoverProps) => {
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = useState<PopoverProps['anchorEl']>();

  const [deleteMutation, deleting] = useApiMutation<PirPopoverDeleteMutation>(
    pirDeleteMutation,
    undefined,
    { successMessage: `${t_i18n('entity_Pir')} ${t_i18n('successfully deleted')}` },
  );

  const deletion = useDeletion({ handleClose: () => setAnchorEl(undefined) });
  const { handleOpenDelete, handleCloseDelete } = deletion;

  const onOpenMenu = (e: UIEvent) => {
    stopEvent(e);
    setAnchorEl(e.currentTarget);
  };

  const onCloseMenu = (e: UIEvent) => {
    stopEvent(e);
    setAnchorEl(undefined);
  };

  const onDelete = (e: UIEvent) => {
    stopEvent(e);
    deleteMutation({
      variables: { id: pirId },
      onCompleted: () => {
        handleCloseDelete();
        onDeleteComplete?.();
      },
      onError: () => {
        handleCloseDelete();
      },
    });
  };

  return (
    <>
      <Button
        onClick={onOpenMenu}
        aria-haspopup="true"
        className="icon-outlined"
        variant="outlined"
      >
        <MoreVert fontSize="small" />
      </Button>

      <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={onCloseMenu}>
        <MenuItem onClick={handleOpenDelete} disabled={deleting}>
          {t_i18n('Delete')}
        </MenuItem>
      </Menu>

      <DeleteDialog
        deletion={deletion}
        submitDelete={onDelete}
        message={t_i18n('Do you want to delete this PIR?')}
      />
    </>
  );
};

export default PirPopover;
