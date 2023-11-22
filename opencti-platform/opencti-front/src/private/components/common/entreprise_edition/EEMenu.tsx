import { styled } from '@mui/material/styles';
import EEChip from '@components/common/entreprise_edition/EEChip';
import React, { ReactElement } from 'react';

const EEDiv = styled('div')(() => ({
  display: 'flex',
}));

const EEMenu = ({ children }: { children: ReactElement }) => {
  return (
    <EEDiv>{children}<EEChip /></EEDiv>
  );
};

export default EEMenu;
