import React, { useState } from 'react';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import ToggleButton from '@mui/material/ToggleButton';
import MoreVert from '@mui/icons-material/MoreVert';
import { graphql } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import { useFormatter } from '../../../../components/i18n';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import { InfrastructureEditionContainerQuery } from './__generated__/InfrastructureEditionContainerQuery.graphql';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import InfrastructureEditionContainer, { infrastructureEditionContainerQuery } from './InfrastructureEditionContainer';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useHelper from '../../../../utils/hooks/useHelper';
import DeleteDialog from '../../../../components/DeleteDialog';
import useDeletion from '../../../../utils/hooks/useDeletion';

const InfrastructurePopoverDeletionMutation = graphql`
  mutation InfrastructurePopoverDeletionMutation($id: ID!) {
    infrastructureEdit(id: $id) {
      delete
    }
  }
`;

const InfrastructurePopover = ({ id }: { id: string }) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const [anchorEl, setAnchorEl] = useState<HTMLElement | null>(null);
  const [displayEdit, setDisplayEdit] = useState<boolean>(false);
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const [commit] = useApiMutation(InfrastructurePopoverDeletionMutation);
  const queryRef = useQueryLoading<InfrastructureEditionContainerQuery>(
    infrastructureEditionContainerQuery,
    { id },
  );
  const handleOpen = (event: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(event.currentTarget);
  };
  const handleClose = () => setAnchorEl(null);
  const deletion = useDeletion({});
  const submitDelete = () => {
    deletion.setDeleting(true);
    commit({
      variables: {
        id,
      },
      onCompleted: () => {
        deletion.setDeleting(false);
        handleClose();
        navigate('/dashboard/observations/infrastructures');
      },
    });
  };
  const handleOpenEdit = () => {
    setDisplayEdit(true);
    handleClose();
  };
  return isFABReplaced
    ? (<></>)
    : (
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
            <MenuItem onClick={deletion.handleOpenDelete}>{t_i18n('Delete')}</MenuItem>
          </Security>
        </Menu>
        <DeleteDialog
          deletion={deletion}
          submitDelete={submitDelete}
          message={t_i18n('Do you want to delete this infrastructure?')}
        />
        {queryRef && (
          <React.Suspense fallback={<div />}>
            <InfrastructureEditionContainer
              queryRef={queryRef}
              handleClose={handleClose}
              open={displayEdit}
            />
          </React.Suspense>
        )}
      </>
    );
};

export default InfrastructurePopover;
