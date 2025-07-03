import React, { useState } from 'react';
import MenuItem from '@mui/material/MenuItem';
import Box from '@mui/material/Box';
import DecayRuleDeletion from '@components/settings/decay/DecayRuleDeletion';
import { DecayRule_decayRule$data } from './__generated__/DecayRule_decayRule.graphql';
import { decayRuleEditionMutation } from './DecayRuleEdition';
import { useFormatter } from '../../../../components/i18n';
import { handleError } from '../../../../relay/environment';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import PopoverMenu from '../../../../components/PopoverMenu';
import useGranted, { KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';

interface DecayRulePopoverProps {
  decayRule: DecayRule_decayRule$data;
}
const DecayRulePopover = ({ decayRule }: DecayRulePopoverProps) => {
  const { t_i18n } = useFormatter();
  const [openDelete, setOpenDelete] = useState(false);
  const canDelete = useGranted([KNOWLEDGE_KNUPDATE_KNDELETE]);

  const handleOpenDelete = () => setOpenDelete(true);
  const handleCloseDelete = () => setOpenDelete(false);

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
    <div>
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
            {canDelete && (
            <MenuItem onClick={() => {
              handleOpenDelete();
              closeMenu();
            }}
            >
              {t_i18n('Delete')}
            </MenuItem>
            )}
          </Box>
        )}
      </PopoverMenu>
      <DecayRuleDeletion
        id={decayRule.id}
        isOpen={openDelete}
        handleClose={handleCloseDelete}
      />
    </div>
  );
};

export default DecayRulePopover;
