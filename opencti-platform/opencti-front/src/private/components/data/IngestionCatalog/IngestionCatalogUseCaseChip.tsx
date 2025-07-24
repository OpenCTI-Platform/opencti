import Chip from '@mui/material/Chip';
import React from 'react';

interface IngestionCatalogChipProps {
  label: string;
  variant?: 'outlined' | 'filled';
  color?: 'primary' | 'secondary' | 'error' | 'success';
}

const IngestionCatalogChip = ({ label, variant, color }: IngestionCatalogChipProps) => {
  return (
    <Chip
      variant={variant ?? 'outlined'}
      size="small"
      color={color ?? 'default'}
      style={{
        margin: '7px 7px 7px 0',
        borderRadius: 4,
      }}
      label={label}
    />
  );
};

export default IngestionCatalogChip;
