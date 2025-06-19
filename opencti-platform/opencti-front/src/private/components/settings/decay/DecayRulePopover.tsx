import React from 'react';
import MenuItem from '@mui/material/MenuItem';
import Box from '@mui/material/Box';
import { DecayRule_decayRule$data } from './__generated__/DecayRule_decayRule.graphql';
import { decayRuleEditionMutation } from './DecayRuleEdition';
import { useFormatter } from '../../../../components/i18n';
import { handleError } from '../../../../relay/environment';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import PopoverMenu from '../../../../components/PopoverMenu';

interface DecayRulePopoverProps {
  decayRule: DecayRule_decayRule$data;
}
const DecayRulePopover = ({ decayRule }: DecayRulePopoverProps) => {
  const { t_i18n } = useFormatter();
  const [commitUpdateMutation] = useApiMutation(decayRuleEditionMutation);

  const submitActivate = () => {
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
    <PopoverMenu>
      {({ closeMenu }) => (
        <Box>
          <MenuItem
            onClick={() => {
              submitActivate();
              closeMenu();
            }}
          >
            {!decayRule.active ? t_i18n('Activate') : t_i18n('Deactivate')}
          </MenuItem>
        </Box>
      )}
    </PopoverMenu>
  );
};

export default DecayRulePopover;
