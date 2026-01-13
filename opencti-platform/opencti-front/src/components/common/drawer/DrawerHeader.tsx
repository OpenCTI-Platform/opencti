import { useTheme } from '@mui/styles';
import { Theme } from '../../Theme';
import { Stack, Typography } from '@mui/material';
import IconButton from '../button/IconButton';
import { Close } from '@mui/icons-material';
import React from 'react';

interface DrawerHeaderProps {
  title: string;
  onClose?: () => void;
  endContent?: React.ReactNode;
}

const DrawerHeader = ({ title, onClose, endContent }: DrawerHeaderProps) => {
  const theme = useTheme<Theme>();
  return (
    <Stack
      direction="row"
      sx={{
        backgroundColor: theme.palette.background.secondary,
        paddingX: 3,
        paddingY: 2,
        alignItems: 'center',
        justifyContent: 'space-between',
      }}
    >
      <Typography
        variant="h5"
        style={{ textWrap: 'nowrap' }}
      >
        {title}
      </Typography>

      <Stack direction="row" alignItems="center" gap={1}>
        {endContent}
        <IconButton
          aria-label="Close"
          onClick={onClose}
          size="default"
        >
          <Close />
        </IconButton>
      </Stack>
    </Stack>
  );
};

export default DrawerHeader;
