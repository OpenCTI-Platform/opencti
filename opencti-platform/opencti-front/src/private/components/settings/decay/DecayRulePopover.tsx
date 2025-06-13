import React, { useState } from 'react';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import IconButton from '@mui/material/IconButton';
import MoreVert from '@mui/icons-material/MoreVert';
import { DecayRule_decayRule$data } from './__generated__/DecayRule_decayRule.graphql';
import { decayRuleEditionMutation } from './DecayRuleEdition';
import { useFormatter } from '../../../../components/i18n';
import { handleError } from '../../../../relay/environment';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

interface DecayRulePopoverProps {
  decayRule: DecayRule_decayRule$data;
}
const DecayRulePopover = ({ decayRule }: DecayRulePopoverProps) => {
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = useState<Element | null>(null);
  const [commitUpdateMutation] = useApiMutation(decayRuleEditionMutation);

  const handleOpen = (event: React.SyntheticEvent) => {
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => {
    setAnchorEl(null);
  };

  const submitActivate = () => {
    handleClose();
    commitUpdateMutation({
      variables: {
        id: decayRule.id,
        input: { key: 'active', value: !decayRule.active },
      },
      onError: (error: Error) => {
        handleError(error);
      },
    });
  };

  return (
    <div style={{ margin: 0 }}>
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
        <MenuItem onClick={submitActivate}>
          {!decayRule.active ? t_i18n('Activate') : t_i18n('Deactivate')}
        </MenuItem>
      </Menu>
    </div>
  );
};

export default DecayRulePopover;
