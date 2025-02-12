import React, { useState } from 'react';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import ToggleButton from '@mui/material/ToggleButton';
import MoreVert from '@mui/icons-material/MoreVert';
import { graphql } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import { individualEditionQuery } from './IndividualEdition';
import IndividualEditionContainer from './IndividualEditionContainer';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import useHelper from '../../../../utils/hooks/useHelper';
import { useFormatter } from '../../../../components/i18n';
import DeleteDialog from '../../../../components/DeleteDialog';
import useDeletion from '../../../../utils/hooks/useDeletion';

const IndividualPopoverDeletionMutation = graphql`
  mutation IndividualPopoverDeletionMutation($id: ID!) {
    individualEdit(id: $id) {
      delete
    }
  }
`;

const IndividualPopover = ({ id }) => {
  const navigate = useNavigate();
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = useState(null);
  const [displayEdit, setDisplayEdit] = useState(false);
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const handleOpen = (event) => setAnchorEl(event.currentTarget);
  const handleClose = () => setAnchorEl(null);
  const deletion = useDeletion({ handleClose });
  const { setDeleting, handleOpenDelete, handleCloseDelete, deleting } = deletion;
  const submitDelete = () => {
    setDeleting(true);
    commitMutation({
      mutation: IndividualPopoverDeletionMutation,
      variables: { id },
      onCompleted: () => {
        setDeleting(false);
        handleClose();
        navigate('/dashboard/entities/individuals');
      },
    });
  };
  const handleOpenEdit = () => {
    setDisplayEdit(true);
    handleClose();
  };
  const handleCloseEdit = () => setDisplayEdit(false);

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
            <MenuItem onClick={handleOpenDelete}>{t_i18n('Delete')}</MenuItem>
          </Security>
        </Menu>
        <DeleteDialog
          deletion={deletion}
          submitDelete={submitDelete}
          message={t_i18n('Do you want to delete this individual?')}
        />
        <QueryRenderer
          query={individualEditionQuery}
          variables={{ id }}
          render={({ props }) => {
            if (props) {
              return (
                <IndividualEditionContainer
                  individual={props.individual}
                  handleClose={handleCloseEdit}
                  open={displayEdit}
                />
              );
            }
            return <div />;
          }}
        />
      </>
    );
};

export default IndividualPopover;
