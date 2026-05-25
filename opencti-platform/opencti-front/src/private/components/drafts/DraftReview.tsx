import React, { FunctionComponent, useCallback, useState } from 'react';
import Box from '@mui/material/Box';
import DraftReviewEntityList, { DraftEntitySelection } from './DraftReviewEntityList';
import DraftReviewDiffPanel from './DraftReviewDiffPanel';

interface DraftReviewProps {
  draftId: string;
}

const DraftReview: FunctionComponent<DraftReviewProps> = ({ draftId }) => {
  const [selectedEntity, setSelectedEntity] = useState<DraftEntitySelection | null>(null);

  const handleSelectEntity = (data: DraftEntitySelection) => {
    setSelectedEntity(data);
  };

  const handleQueryChange = useCallback(() => setSelectedEntity(null), []);

  const [containerRef, setContainerRef] = useState<HTMLDivElement | undefined>(undefined);

  return (
    <Box
      sx={{
        display: 'flex',
        gap: 2,
        height: 'calc(100vh - 250px)',
        minHeight: 400,
      }}
    >
      {/* Left column — entity list */}
      <Box sx={{ flex: 1, minWidth: 0, overflow: 'hidden' }} ref={(r: HTMLDivElement | null) => setContainerRef(r ?? undefined)}>
        <DraftReviewEntityList
          draftId={draftId}
          onSelectEntity={handleSelectEntity}
          onQueryChange={handleQueryChange}
          rootRef={containerRef}
        />
      </Box>
      {/* Right column — diff panel */}

      <Box sx={{ flex: 2, overflowY: 'auto', padding: 2 }}>
        <DraftReviewDiffPanel
          draftId={draftId}
          entity={selectedEntity}
        />
      </Box>
    </Box>
  );
};

export default DraftReview;
