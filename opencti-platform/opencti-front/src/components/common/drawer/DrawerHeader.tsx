import { Stack, Typography } from '@mui/material';
import IconButton from '../button/IconButton';
import { Close } from '@mui/icons-material';
import React from 'react';
import { SURFACE_LAYER, fdsLayerClass, layerInputVars } from '../../../utils/fdsLayer';

interface DrawerHeaderProps {
  title: string;
  layer?: Parameters<typeof fdsLayerClass>[0];
  onClose?: () => void;
  endContent?: React.ReactNode;
}

const DrawerHeader = ({ title, onClose, endContent, layer = SURFACE_LAYER }: DrawerHeaderProps) => {
  return (
    <Stack
      direction="row"
      className={fdsLayerClass(layer)}
      sx={{
        ...layerInputVars,
        backgroundColor: 'var(--bg-elevation-heading)',
        paddingX: 3,
        paddingY: 2,
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: 2,
      }}
    >
      {/* minWidth 0 lets a long title shrink and be cut, instead of pushing the actions out of the drawer */}
      <Typography
        id="drawer-title"
        variant="h5"
        title={title}
        style={{ textWrap: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', minWidth: 0 }}
      >
        {title}
      </Typography>

      <Stack direction="row" alignItems="center" gap={1} sx={{ flexShrink: 0 }}>
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
