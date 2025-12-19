/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import React, { UIEvent, useState } from 'react';
import MoreVert from '@mui/icons-material/MoreVert';
import IconButton from '@common/button/IconButton';
import { Menu, MenuItem, PopoverProps } from '@mui/material';
import { graphql, useFragment } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import { PirPopoverFragment$key } from './__generated__/PirPopoverFragment.graphql';
import { useFormatter } from '../../../components/i18n';
import stopEvent from '../../../utils/domEvent';
import PirDeletion from './PirDeletion';

const popoverFragment = graphql`
  fragment PirPopoverFragment on Pir {
    id
  }
`;

interface PirPopoverProps {
  data: PirPopoverFragment$key;
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
