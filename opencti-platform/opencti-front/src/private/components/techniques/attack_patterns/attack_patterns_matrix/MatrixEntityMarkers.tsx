import React from 'react';
import { Box } from '@mui/material';
import MatrixEntityMarker, { MarkerShape } from './MatrixEntityMarker';

export interface MatrixCellEntity {
  id: string;
  name: string;
  color: string;
  shape: MarkerShape;
}

interface MatrixEntityMarkersProps {
  entities: MatrixCellEntity[];
}

// Renders the entity markers shown inside a technique / sub-technique cell.
// Markers flow horizontally and fill the available width, wrapping onto a new
// line only when they run out of horizontal space.
const MatrixEntityMarkers = ({ entities }: MatrixEntityMarkersProps) => {
  if (!entities || entities.length === 0) {
    return null;
  }

  return (
    <Box sx={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 0.5 }}>
      {entities.map((entity) => (
        <MatrixEntityMarker
          key={entity.id}
          shape={entity.shape}
          color={entity.color}
          label={entity.name}
        />
      ))}
    </Box>
  );
};

export default MatrixEntityMarkers;
