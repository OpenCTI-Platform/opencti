import React from 'react';
import Box from '@mui/material/Box';
import IngestionCatalogChip from '@components/data/IngestionCatalog/IngestionCatalogUseCaseChip';

type ChipWrapperProps = {
  useCase: string;
  isVisible: boolean;
  canShrink?: boolean;
  chipRef: (el: HTMLDivElement | null) => void;
};

const ChipWrapper = ({ useCase, isVisible, canShrink, chipRef }: ChipWrapperProps) => (
  <Box
    ref={chipRef}
    sx={{
      flexShrink: canShrink ? 1 : 0, // Only shrink if allowed
      minWidth: canShrink ? 0 : 'auto', // Required for ellipsis
      visibility: isVisible ? 'visible' : 'hidden',
      position: isVisible ? 'relative' : 'absolute',
    }}
  >
    <IngestionCatalogChip withTooltip={true} isInTooltip label={useCase} color="primary" />
  </Box>
);

export default ChipWrapper;
