import React, { useState } from 'react';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import ToggleButton from '@mui/material/ToggleButton';
import MoreVert from '@mui/icons-material/MoreVert';
import { graphql } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import { PopoverProps } from '@mui/material/Popover';
import { useFormatter } from '../../../../components/i18n';
import IncidentEditionContainer, { IncidentEditionQuery } from './IncidentEditionContainer';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import useDeletion from '../../../../utils/hooks/useDeletion';
import { IncidentEditionContainerQuery } from './__generated__/IncidentEditionContainerQuery.graphql';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import DeleteDialog from '../../../../components/DeleteDialog';

const IncidentPopoverDeletionMutation = graphql`
  mutation IncidentPopoverDeletionMutation($id: ID!) {
    incidentEdit(id: $id) {
      delete
    }
  }
`;

const IncidentPopover = ({ id }: { id: string }) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const [anchorEl, setAnchorEl] = useState<PopoverProps['anchorEl']>();
  const [displayEdit, setDisplayEdit] = useState<boolean>(false);
  const [commit] = useApiMutation(IncidentPopoverDeletionMutation);
  const queryRef = useQueryLoading<IncidentEditionContainerQuery>(
    IncidentEditionQuery,
    { id },
  );
  const handleOpen = (event: React.SyntheticEvent) => {
    setAnchorEl(event.currentTarget);
  };
  const handleClose = () => {
    setAnchorEl(undefined);
  };
  const handleOpenEdit = () => {
    setDisplayEdit(true);
    handleClose();
  };
  const handleCloseEdit = () => {
    setDisplayEdit(false);
  };
  const deletion = useDeletion({ handleClose });
  const { setDeleting, handleOpenDelete } = deletion;
  const submitDelete = () => {
    setDeleting(true);
    commit({
      variables: {
        id,
      },
      onCompleted: () => {
        setDeleting(false);
        handleClose();
        navigate('/dashboard/events/incidents');
      },
    });
  };

  return (
    <>
      <ToggleButton
        value="popover"
        size="small"
        onClick={handleOpen}
      >
        <MoreVert fontSize="small" color="primary" />
      </ToggleButton>
      <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleClose}>
        <MenuItem onClick={handleOpenEdit}>{t_i18n('Update')}</MenuItem>
        <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
          <MenuItem onClick={handleOpenDelete}>{t_i18n('Delete')}</MenuItem>
        </Security>
      </Menu>
      <DeleteDialog
        deletion={deletion}
        submitDelete={submitDelete}
        message={t_i18n('Do you want to delete this incident?')}
      />
      {queryRef && (
      <React.Suspense fallback={<div />}>
        <IncidentEditionContainer
          queryRef={queryRef}
          handleClose={handleCloseEdit}
          open={displayEdit}
        />
      </React.Suspense>
      )}
    </>
  );
};

export default IncidentPopover;
