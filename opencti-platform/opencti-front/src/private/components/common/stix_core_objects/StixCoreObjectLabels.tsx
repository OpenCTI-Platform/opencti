import Tag from '@common/tag/Tag';
import { Box, Stack } from '@mui/material';
import { useTheme } from '@mui/material/styles';
import React, { SyntheticEvent } from 'react';
import { useFormatter } from '../../../../components/i18n';
import { HandleAddFilter } from '../../../../utils/hooks/useLocalStorage';
import useChipOverflow from '../../data/IngestionCatalog/components/card/usecases/useChipOverflow';
import { Theme } from '../../../../components/Theme';

interface StixCoreObjectLabelsProps {
  labels: readonly {
    readonly color: string | null | undefined;
    readonly id: string;
    readonly value: string | null | undefined;
  }[] | null | undefined;
  onClick?: HandleAddFilter;
  variant?: string;
  revoked?: boolean;
}

const StixCoreObjectLabels = ({
  labels,
  onClick,
  revoked,
}: StixCoreObjectLabelsProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const labelValues = labels?.map((l) => l.value || l.id) ?? [];
  const { containerRef, chipRefs, visibleCount, shouldTruncate } = useChipOverflow(labelValues);

  if (!revoked && labels && labels.length > 0) {
    const hiddenCount = labels.length - visibleCount;

    return (
      <div
        ref={containerRef}
        style={{
          display: 'flex',
          flexWrap: 'nowrap',
          alignItems: 'center',
          overflow: 'hidden',
          width: '100%',
          position: 'relative',
          gap: '8px',
        }}
      >
        {/* Render the chips, but keep it hidden so we can useChipOverflow calculate
            the width remaining by chip to know if it should truncate or not */}
        <Stack direction="row" position="absolute" visibility="hidden" gap={1}>
          {labels.map((label, index) => (
            <div
              key={label.id}
              ref={(el) => {
                chipRefs.current[index] = el;
              }}
            >
              <Tag label={label.value || '-'} />
            </div>
          ))}
        </Stack>

        {/* Visible chips */}
        <Stack direction="row" gap={1} overflow="hidden" flex={1}>
          {labels.slice(0, visibleCount).map((label) => (
            <Box key={label.id} sx={{ minWidth: 0 }}>
              <Tag
                label={label.value || ''}
                color={label.color || ''}
                onClick={(e: React.MouseEvent) => {
                  e.preventDefault();
                  e.stopPropagation();
                  onClick?.('objectLabel', label.id, 'eq');
                }}
              />
            </Box>
          ))}
        </Stack>

        {shouldTruncate && hiddenCount > 0 && (
          <Tag
            label={`+${hiddenCount}`}
            color={theme.tag.overflowColor}
            tooltipTitle={labels.slice(visibleCount).map((l) => l.value).join(', ')}
          />
        )}
      </div>
    );
  }

  return (
    <>
      {revoked ? (
        <Tag
          variant="outlined"
          label={t_i18n('Revoked')}
          onClick={(e: SyntheticEvent) => {
            e.preventDefault();
            e.stopPropagation();
            onClick?.('objectLabel', null, 'eq');
          }}
          color={theme.palette.designSystem.tertiary.red[400]}
        />
      ) : (
        <Tag
          label={t_i18n('No label')}
          onClick={(e: SyntheticEvent) => {
            e.preventDefault();
            e.stopPropagation();
            onClick?.('objectLabel', null, 'eq');
          }}
          color={theme.palette.designSystem.tertiary.blue[900]}
        />
      )}
    </>
  );
};

export default StixCoreObjectLabels;
