import { useTheme } from '@mui/styles';
import { Theme } from '../../Theme';
import { FDS } from '../../fds-tokens.generated';
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
  // Figma node 5415-3010 (Design_System_2026) draws the drawer on elevation
  // LAYER 2, not on the bare alias. Read straight off that node, the header is
  // #101b33 and the body #13213e in dark -- which are `-layer-2`, while the
  // unsuffixed `--bg-elevation-*` aliases resolve to layer 0 (#070d18). Two
  // independent hexes both landing on layer 2 is what fixes the layer; taking
  // the bare alias would have painted the drawer a full step too dark.
  // Colours only: the structural conversion to a library drawer comes later.
  const fds = theme.palette.mode === 'light' ? FDS.colors.light : FDS.colors.dark;
  return (
    <Stack
      direction="row"
      sx={{
        backgroundColor: fds['--bg-elevation-heading-layer-2'],
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
