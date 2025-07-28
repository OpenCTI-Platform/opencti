import React, { UIEvent, useState } from 'react';
import MoreVert from '@mui/icons-material/MoreVert';
import Button from '@mui/material/Button';
import { Menu, MenuItem, PopoverProps } from '@mui/material';
import { graphql, useFragment } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import { useFormatter } from '../../../components/i18n';
import stopEvent from '../../../utils/domEvent';
import PirDeletion from './PirDeletion';
import { PirPopoverFragment$key } from './__generated__/PirPopoverFragment.graphql';

const popoverFragment = graphql`
  fragment PirPopoverFragment on Pir {
    id
  }
`;

interface PirPopoverProps {
  data: PirPopoverFragment$key
}

const PirPopover = ({ data }: PirPopoverProps) => {
  const navigate = useNavigate();
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = useState<PopoverProps['anchorEl']>();

  const { id } = useFragment(popoverFragment, data);

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
      <Button
        onClick={onOpenMenu}
        aria-haspopup="true"
        className="icon-outlined"
        variant="outlined"
      >
        <MoreVert fontSize="small" />
      </Button>

      <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={onCloseMenu}>
        <PirDeletion
          pirId={id}
          onDeleteComplete={() => navigate('/dashboard/pirs')}
        >
          {({ handleOpenDelete, deleting }) => (
            <MenuItem onClick={handleOpenDelete} disabled={deleting}>
              {t_i18n('Delete')}
            </MenuItem>
          )}
        </PirDeletion>
      </Menu>
    </>
  );
};

export default PirPopover;
