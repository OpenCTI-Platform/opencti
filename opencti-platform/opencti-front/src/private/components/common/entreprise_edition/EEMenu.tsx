import EEChip from '@components/common/entreprise_edition/EEChip';
import React, { ReactElement } from 'react';
import { Stack } from '@mui/material';

type EEMenuProps = {
  children: ReactElement,
};

const EEMenu = ({ children }: EEMenuProps) => {
  return (
    <Stack direction="row">
      {children}
      <EEChip />
    </Stack>
  );
};

export default EEMenu;
