import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import Dialog from '@common/dialog/Dialog';
import MoreVert from '@mui/icons-material/MoreVert';
import DialogActions from '@mui/material/DialogActions';
import DialogContentText from '@mui/material/DialogContentText';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Slide from '@mui/material/Slide';
import withStyles from '@mui/styles/withStyles';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import React, { useState } from 'react';
import { graphql } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import { deleteNode } from '../../../../utils/store';
import RetentionEdition from './RetentionEdition';

const styles = () => ({
  container: {
    margin: 0,
  },
});

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const retentionPopoverDeletionMutation = graphql`
  mutation RetentionPopoverDeletionMutation($id: ID!) {
    retentionRuleEdit(id: $id) {
      delete
    }
  }
`;

const retentionPopoverFieldPatchMutation = graphql`
  mutation RetentionPopoverFieldPatchMutation($id: ID!, $input: [EditInput]!) {
    retentionRuleEdit(id: $id) {
      fieldPatch(input: $input) {
        id
        active
      }
    }
  }
`;

const retentionEditionQuery = graphql`
  query RetentionPopoverEditionQuery($id: String!) {
    retentionRule(id: $id) {
      id
      name
      max_retention
      filters
      active
      scope
      ...RetentionEdition_retentionRule
    }
  }
`;

const RetentionPopover = (props) => {
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = useState(null);
  const [displayUpdate, setDisplayUpdate] = useState(false);
  const [displayDelete, setDisplayDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);
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

  const submitDelete = () => {
    setDeleting(true);
    commitMutation({
      mutation: retentionPopoverDeletionMutation,
      variables: {
        id: props.retentionRuleId,
      },
      updater: (store) => {
        deleteNode(
          store,
          'Pagination_retentionRules',
          props.paginationOptions,
          props.retentionRuleId,
        );
      },
      onCompleted: () => {
        setDeleting(false);
        handleCloseDelete();
      },
    });
  };

  const submitToggleActive = (currentActive) => {
    commitMutation({
      mutation: retentionPopoverFieldPatchMutation,
      variables: {
        id: props.retentionRuleId,
        input: [{ key: 'active', value: [String(!currentActive)] }],
      },
    });
    handleClose();
  };

  const { classes, retentionRuleId } = props;
  return (
    <div className={classes.container}>
      <IconButton
        aria-label={t_i18n('Open menu')}
        onClick={handleOpen}
        aria-haspopup="true"
        color="primary"
      >
        <MoreVert />
      </IconButton>
      <QueryRenderer
        query={retentionEditionQuery}
        variables={{ id: retentionRuleId }}
        render={({ props }) => {
          if (props) {
            const { retentionRule } = props;
            const isTechnicalRule = retentionRule?.scope && retentionRule.scope !== 'knowledge';
            return (
              <>
                <Menu
                  anchorEl={anchorEl}
                  open={Boolean(anchorEl)}
                  onClose={handleClose}
                >
                  <MenuItem onClick={handleOpenUpdate}>
                    {t_i18n('Update')}
                  </MenuItem>
                  <MenuItem onClick={() => submitToggleActive(retentionRule?.active)}>
                    {retentionRule?.active ? t_i18n('Deactivate') : t_i18n('Activate')}
                  </MenuItem>
                  {!isTechnicalRule && (
                    <MenuItem onClick={handleOpenDelete}>
                      {t_i18n('Delete')}
                    </MenuItem>
                  )}
                </Menu>
                <RetentionEdition
                  retentionRule={retentionRule}
                  handleClose={handleCloseUpdate}
                  open={displayUpdate}
                />
              </>
            );
          }
          return (
            <Menu
              anchorEl={anchorEl}
              open={Boolean(anchorEl)}
              onClose={handleClose}
            >
              <MenuItem onClick={handleOpenUpdate}>
                {t_i18n('Update')}
              </MenuItem>
            </Menu>
          );
        }}
      />
      <Dialog
        open={displayDelete}
        onClose={handleCloseDelete}
        title={t_i18n('Are you sure?')}
      >
        <DialogContentText>
          {t_i18n('Do you want to delete this retention policy?')}
        </DialogContentText>
        <DialogActions>
          <Button
            variant="secondary"
            onClick={handleCloseDelete}
            disabled={deleting}
          >
            {t_i18n('Cancel')}
          </Button>
          <Button
            onClick={submitDelete}
            disabled={deleting}
          >
            {t_i18n('Confirm')}
          </Button>
        </DialogActions>
      </Dialog>
    </div>
  );
};

RetentionPopover.propTypes = {
  retentionRuleId: PropTypes.string,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
};

export default compose(withStyles(styles))(RetentionPopover);
