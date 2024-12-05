import React, { useState } from 'react';
import { graphql } from 'react-relay';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import MoreVert from '@mui/icons-material/MoreVert';
import { useFormatter } from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import MarkingDefinitionEdition from './MarkingDefinitionEdition';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { deleteNode } from '../../../../utils/store';
import Transition from '../../../../components/Transition';
import useSensitiveModifications from '../../../../utils/hooks/useSensitiveModifications';

const markingDefinitionPopoverDeletionMutation = graphql`
  mutation MarkingDefinitionPopoverDeletionMutation($id: ID!) {
    markingDefinitionEdit(id: $id) {
      delete
    }
  }
`;

const markingDefinitionEditionQuery = graphql`
  query MarkingDefinitionPopoverEditionQuery($id: String!) {
    markingDefinition(id: $id) {
      editContext {
          name
          focusOn
      }
      ...MarkingDefinitionEdition_markingDefinition
    }
  }
`;

const MarkingDefinitionPopover = ({
  markingDefinition, paginationOptions,
}) => {
  const { t_i18n } = useFormatter();
  const { isSensitive, isAllowed } = useSensitiveModifications('markings', markingDefinition.standard_id);
  const [anchorEl, setAnchorEl] = useState(null);
  const [displayUpdate, setDisplayUpdate] = useState(false);
  const [displayDelete, setDisplayDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const disabled = !isAllowed && isSensitive;

  const handleOpen = (event) => {
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => {
    setAnchorEl(null);
  };

  const handleOpenUpdate = () => {
    setDisplayUpdate(true);
    handleClose();
  };

  const handleCloseUpdate = () => {
    setDisplayUpdate(false);
  };

  const handleOpenDelete = () => {
    setDisplayDelete(true);
    handleClose();
  };

  const handleCloseDelete = () => {
    setDisplayDelete(false);
  };

  const [commit] = useApiMutation(markingDefinitionPopoverDeletionMutation);

  const submitDelete = () => {
    setDeleting(true);
    commit({
      variables: {
        id: markingDefinition.id,
      },
      updater: (store) => {
        deleteNode(store, 'Pagination_markingDefinitions', paginationOptions, markingDefinition.id);
      },
      onCompleted: () => {
        setDeleting(false);
        handleCloseDelete();
      },
    });
  };

  return (
    <div style={{ margin: 0 }}>
      <IconButton
        onClick={handleOpen}
        aria-haspopup="true"
        size="large"
        disabled={disabled}
        color="primary"
      >
        <MoreVert />
      </IconButton>
      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={handleClose}
      >
        <MenuItem onClick={handleOpenUpdate}>
          {t_i18n('Update')}
        </MenuItem>
        <MenuItem onClick={handleOpenDelete}>
          {t_i18n('Delete')}
        </MenuItem>
      </Menu>
      <QueryRenderer
        query={markingDefinitionEditionQuery}
        variables={{ id: markingDefinition.id }}
        render={({ props }) => {
          if (props) {
            return (
              <MarkingDefinitionEdition
                markingDefinition={props.markingDefinition}
                handleClose={handleCloseUpdate}
                open={displayUpdate}
              />
            );
          }
          return <div />;
        }}
      />
      <Dialog
        open={displayDelete}
        PaperProps={{ elevation: 1 }}
        keepMounted={true}
        TransitionComponent={Transition}
        onClose={handleCloseDelete}
      >
        <DialogContent>
          <DialogContentText>
            {t_i18n('Do you want to delete this marking definition?')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button
            onClick={handleCloseDelete}
            disabled={deleting}
          >
            {t_i18n('Cancel')}
          </Button>
          <Button
            color="secondary"
            onClick={submitDelete}
            disabled={deleting}
          >
            {t_i18n('Delete')}
          </Button>
        </DialogActions>
      </Dialog>
    </div>
  );
};

export default MarkingDefinitionPopover;
