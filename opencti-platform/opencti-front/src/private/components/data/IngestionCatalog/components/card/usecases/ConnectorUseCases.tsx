import React from 'react';
import useChipOverflow from '@components/data/IngestionCatalog/components/card/usecases/useChipOverflow';
import { Stack } from '@mui/material';
import ChipWrapper from '@components/data/IngestionCatalog/components/card/usecases/ChipWrapper';
import Box from '@mui/material/Box';
import IngestionCatalogChip from '@components/data/IngestionCatalog/IngestionCatalogUseCaseChip';

type ConnectorUseCasesProps = {
  useCases: string[]
};

const ConnectorUseCases = ({ useCases }: ConnectorUseCasesProps) => {
  const { containerRef, chipRefs, visibleCount } = useChipOverflow(useCases);

  const hiddenCount = useCases.length - visibleCount;
  const hasOverflow = hiddenCount > 0;
  const hiddenUseCases = useCases.slice(visibleCount);

  return (
    <Stack
      direction="row"
      spacing={1}
      ref={containerRef}
      sx={{ overflow: 'hidden', flexWrap: 'nowrap', position: 'relative' }}
    >
      {
        // Show the usecase chips,
        // - if last one has enough space, show full chip
        // - not enough remaining space, but still can show text, truncate it
        // - not enough remaining space for text, show +1 instead of usecase truncated

        useCases.map((useCase: string, index: number) => {
          const isVisible = index < visibleCount;
          const isLastVisible = index === visibleCount - 1;

          return (
            <ChipWrapper
              key={useCase}
              useCase={useCase}
              isVisible={isVisible}
              canShrink={isLastVisible} // Only last visible chip can shrink
              chipRef={(el: HTMLDivElement | null) => {
                chipRefs.current[index] = el;
              }}
            />
          );
        })
      }

      {
        hasOverflow && (
          <Box sx={{ flexShrink: 0 }}>
            <IngestionCatalogChip
              withTooltip={true}
              isInTooltip
              label={`+${hiddenCount}`}
              tooltipLabel={hiddenUseCases.join(', ')}
              color="primary"
            />
          </Box>
        )
      }
    </Stack>
  );
};

export default ConnectorUseCases;
