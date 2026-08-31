import { Stack, Typography } from '@mui/material';
import IconButton from '../button/IconButton';
import { Close } from '@mui/icons-material';
import React from 'react';
import { SURFACE_LAYER, fdsLayerClass, layerInputVars } from '../../../utils/fdsLayer';

interface DrawerHeaderProps {
  title: string;
  /**
   * The elevation layer this header sits on.
   */
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
        // Resolves to the layer-2 value: the drawer paper declares layer 2.
        backgroundColor: 'var(--bg-elevation-heading)',
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
