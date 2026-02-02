import React from 'react';
import CheckIcon from '@mui/icons-material/Check';
import CloseIcon from '@mui/icons-material/Close';
import { useTheme } from '@mui/material/styles';
import { Theme } from '../../Theme';

interface BooleanStatusIconProps {
  status?: boolean | null;
}

const BooleanStatusIcon: React.FC<BooleanStatusIconProps> = ({ status }) => {
  const theme = useTheme<Theme>();

  return (status ?? false)
    ? <CheckIcon sx={{ color: theme.palette.designSystem.tertiary.green[600] }} />
    : <CloseIcon sx={{ color: theme.palette.designSystem.tertiary.red[700] }} />;
};

export default BooleanStatusIcon;
