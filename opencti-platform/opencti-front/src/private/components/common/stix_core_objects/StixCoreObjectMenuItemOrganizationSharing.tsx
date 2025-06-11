import MenuItem from '@mui/material/MenuItem';
import EETooltip from '@components/common/entreprise_edition/EETooltip';
import React, { FunctionComponent } from 'react';
import { useFormatter } from '../../../../components/i18n';

interface StixCoreObjectMenuItemOrganizationSharingProps {
  isOrgaSharingPossible: boolean
  orgaSharingNotPossibleMessage?: string,
  setOpenSharing: (v: boolean) => void,
  handleCloseMenu: () => void,
}

const StixCoreObjectMenuItemOrganizationSharing: FunctionComponent<StixCoreObjectMenuItemOrganizationSharingProps> = ({
  isOrgaSharingPossible,
  orgaSharingNotPossibleMessage,
  setOpenSharing,
  handleCloseMenu,
}) => {
  const { t_i18n } = useFormatter();
  return (
    <EETooltip title={orgaSharingNotPossibleMessage}>
      <span>
        <MenuItem
          onClick={() => {
            setOpenSharing(true);
            handleCloseMenu();
          }}
          disabled={!isOrgaSharingPossible}
        >
          {t_i18n('Share with an organization')}
        </MenuItem>
      </span>
    </EETooltip>
  );
};

export default StixCoreObjectMenuItemOrganizationSharing;
