import Chip from '@mui/material/Chip';
import React from 'react';

const IngestionCatalogUseCaseChip = ({ useCase }: { useCase: string }) => {
  return (
    <Chip
      key={useCase}
      variant="outlined"
      size="small"
      style={{
        margin: '7px 7px 7px 0',
        borderRadius: 4,
      }}
      label={useCase}
    />
  );
};

export default IngestionCatalogUseCaseChip;
