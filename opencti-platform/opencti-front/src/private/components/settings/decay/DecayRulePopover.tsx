import React, { useState } from 'react';
import { graphql } from 'react-relay';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import IconButton from '@mui/material/IconButton';
import MoreVert from '@mui/icons-material/MoreVert';
import makeStyles from '@mui/styles/makeStyles';
import { useNavigate } from 'react-router-dom';
import { DecayRule_decayRule$data } from './__generated__/DecayRule_decayRule.graphql';
import { decayRuleEditionMutation } from './DecayRuleEdition';
import { useFormatter } from '../../../../components/i18n';
import { handleError } from '../../../../relay/environment';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import DeleteDialog from '../../../../components/DeleteDialog';
import useDeletion from '../../../../utils/hooks/useDeletion';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
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
  const [commitDeleteMutation] = useApiMutation(decayRuleDeletionMutation);
  const [commitUpdateMutation] = useApiMutation(decayRuleEditionMutation);

  const handleOpen = (event: React.SyntheticEvent) => {
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => {
    setAnchorEl(null);
  };

  const deletion = useDeletion({ handleClose });
  const { setDeleting, handleOpenDelete, handleCloseDelete } = deletion;
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
      <DeleteDialog
        deletion={deletion}
        submitDelete={submitDelete}
        message={t_i18n('Do you want to delete this entity?')}
      />
    </div>
  );
};

export default DecayRulePopover;
