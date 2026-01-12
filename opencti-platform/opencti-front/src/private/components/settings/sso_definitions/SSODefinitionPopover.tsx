import { graphql, useFragment } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import { useFormatter } from '../../../../components/i18n';
import React, { UIEvent, useState } from 'react';
import { Menu, MenuItem, PopoverProps } from '@mui/material';
import stopEvent from '../../../../utils/domEvent';
import IconButton from '@common/button/IconButton';
import MoreVert from '@mui/icons-material/MoreVert';
import SSODefinitionDeletion from '@components/settings/sso_definitions/SSODefinitionDeletion';
import { SSODefinitionPopoverFragment$key } from '@components/settings/sso_definitions/__generated__/SSODefinitionPopoverFragment.graphql';

const ssoDefinitionPopoverFragment = graphql`
  fragment SSODefinitionPopoverFragment on SingleSignOn {
    id
  }
`;

interface SsoDefinitionPopoverProps {
  data: SSODefinitionPopoverFragment$key;
}

export const SSODefinitionPopover = ({ data }: SsoDefinitionPopoverProps) => {
  const navigate = useNavigate();
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = useState<PopoverProps['anchorEl']>();

  const { id } = useFragment(ssoDefinitionPopoverFragment, data);

  const onOpenMenu = (e: UIEvent) => {
    stopEvent(e);
    setAnchorEl(e.currentTarget);
  };

  const onCloseMenu = (e: UIEvent) => {
    stopEvent(e);
    setAnchorEl(undefined);
  };

  return (
    <>
      <IconButton
        onClick={onOpenMenu}
        aria-haspopup="true"
        className="icon-outlined"
        variant="secondary"
        aria-label={t_i18n('Popover of actions')}
      >
        <MoreVert fontSize="small" />
      </IconButton>

      <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={onCloseMenu}>
        <SSODefinitionDeletion
          ssoId={id}
          onDeleteComplete={() => navigate('/dashboard/settings/accesses/single_sign_ons')}
        >
          {({ handleOpenDelete, deleting }) => (
            <MenuItem onClick={handleOpenDelete} disabled={deleting}>
              {t_i18n('Delete')}
            </MenuItem>
          )}
        </SSODefinitionDeletion>
      </Menu>
    </>
  );
};

export default SSODefinitionPopover;
