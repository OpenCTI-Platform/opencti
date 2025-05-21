import { graphql } from 'react-relay';
import React, { FunctionComponent, useState } from 'react';
import MoreVert from '@mui/icons-material/MoreVert';
import IconButton from '@mui/material/IconButton';
import MenuItem from '@mui/material/MenuItem';
import Menu from '@mui/material/Menu';
import { useNavigate } from 'react-router-dom';
import { FintelDesign_fintelDesign$data } from '@components/settings/fintel_design/__generated__/FintelDesign_fintelDesign.graphql';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useDeletion from '../../../../utils/hooks/useDeletion';
import DeleteDialog from '../../../../components/DeleteDialog';

const fintelDesignPopoverDeletionMutation = graphql`
  mutation FintelDesignPopoverDeletionMutation($id: ID!) {
    fintelDesignDelete(id: $id)
  }
`;

interface FintelDesignPopoverProps {
  data: FintelDesign_fintelDesign$data;
}

const FintelDesignPopover: FunctionComponent<FintelDesignPopoverProps> = ({
  data,
}) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();

  const [anchorEl, setAnchorEl] = useState<HTMLElement | null>(null);

  const [commitDelete] = useApiMutation(fintelDesignPopoverDeletionMutation);

  //  popover
  const handleOpen = (event: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(event.currentTarget);
  };
  const handleClose = () => setAnchorEl(null);

  // delete
  const deletion = useDeletion({ handleClose });
  const { setDeleting, handleCloseDelete, handleOpenDelete } = deletion;
  const submitDelete = () => {
    commitDelete({
      variables: {
        id: data.id,
      },
      onCompleted: () => {
        setDeleting(false);
        handleCloseDelete();
        navigate('/dashboard/settings/customization/fintel_designs');
      },
    });
  };

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
        <MenuItem onClick={handleOpenDelete}>{t_i18n('Delete')}</MenuItem>
      </Menu>
      <DeleteDialog
        deletion={deletion}
        submitDelete={submitDelete}
        message={t_i18n('Do you want to delete this fintel design?')}
      />
    </>
  );
};

export default FintelDesignPopover;
