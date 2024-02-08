import React, { useState } from 'react';
import { graphql, useMutation } from 'react-relay';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import MoreVert from '@mui/icons-material/MoreVert';
import makeStyles from '@mui/styles/makeStyles';
import { useNavigate } from 'react-router-dom-v5-compat';
import { DecayRule_decayRule$data } from './__generated__/DecayRule_decayRule.graphql';
import { decayRuleEditionMutation } from './DecayRuleEdition';
import Transition from '../../../../components/Transition';
import { useFormatter } from '../../../../components/i18n';
import { handleError } from '../../../../relay/environment';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
  },
}));

const decayRuleDeletionMutation = graphql`
  mutation DecayRulePopoverDeletionMutation($id: ID!) {
    decayRuleDelete(id: $id)
  }
`;

interface DecayRulePopoverProps {
  decayRule: DecayRule_decayRule$data;
}
const DecayRulePopover = ({ decayRule }: DecayRulePopoverProps) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const [anchorEl, setAnchorEl] = useState<Element | null>(null);
  const [displayDelete, setDisplayDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [commitDeleteMutation] = useMutation(decayRuleDeletionMutation);
  const [commitUpdateMutation] = useMutation(decayRuleEditionMutation);

  const handleOpen = (event: React.SyntheticEvent) => {
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => {
    setAnchorEl(null);
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
    commitDeleteMutation({
      variables: {
        id: decayRule.id,
      },
      onCompleted: () => {
        setDeleting(false);
        handleCloseDelete();
        navigate('/dashboard/settings/customization/decay');
      },
      onError: (error: Error) => {
        handleError(error);
        handleCloseDelete();
      },
    });
  };

  const submitActivate = () => {
    commitUpdateMutation({
      variables: {
        id: decayRule.id,
        input: { key: 'active', value: !decayRule.active },
      },
      onCompleted: () => {
        // TODO success message ?
        handleClose();
      },
      onError: (error: Error) => {
        handleError(error);
        handleClose();
      },
    });
  };

  return (
    <div className={classes.container}>
      <IconButton
        onClick={(event) => handleOpen(event)}
        aria-haspopup="true"
        size="large"
        style={{ marginTop: 3 }}
        color="primary"
      >
        <MoreVert />
      </IconButton>
      <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleClose}>
        <MenuItem onClick={submitActivate}>{!decayRule.active ? t_i18n('Activate') : t_i18n('Deactivate')}</MenuItem>
        <MenuItem onClick={handleOpenDelete}>{t_i18n('Delete')}</MenuItem>
      </Menu>

      <Dialog
        open={displayDelete}
        PaperProps={{ elevation: 1 }}
        keepMounted={true}
        TransitionComponent={Transition}
        onClose={handleCloseDelete}
      >
        <DialogContent>
          <DialogContentText>
            {t_i18n('Do you want to delete this entity?')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseDelete} disabled={deleting}>
            {t_i18n('Cancel')}
          </Button>
          <Button color="secondary" onClick={submitDelete} disabled={deleting}>
            {t_i18n('Delete')}
          </Button>
        </DialogActions>
      </Dialog>
    </div>
  );
};

export default DecayRulePopover;
