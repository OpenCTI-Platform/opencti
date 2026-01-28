import { Stack } from '@mui/material';
import React from 'react';
import Tag from './Tag';
import { useTagsOverflowDetection } from './useTagsOverflowDetection';

interface TagsOverflowProps<T> {
  items: readonly T[] | T[];
  getKey: (item: T) => string;
  getLabel?: (item: T) => string;
  renderTag: (item: T) => React.ReactNode;
  maxWidth?: string;
  gapPx?: number;
  children?: React.ReactNode;
  direction?: 'ltr' | 'rtl';
  onTagCounterClick?: () => void;
}

export function TagsOverflow<T>({
  items,
  getKey,
  getLabel,
  renderTag,
  onTagCounterClick,
  maxWidth = '100%',
  gapPx = 8,
  children,
  direction = 'ltr',
}: TagsOverflowProps<T>) {
  const {
    measureContainerRef,
    visibleContainerRef,
    visibleCount,
    overflowCount,
    isRTL,
  } = useTagsOverflowDetection({
    totalCount: items.length,
    gapPx,
    direction,
  });

  const visibleItems = (items as T[]).slice(0, visibleCount);
  const displayItems = isRTL ? [...visibleItems].reverse() : visibleItems;

  const hiddenItems = (items as T[]).slice(visibleCount);
  const tooltipTitle = getLabel
    ? hiddenItems.map((item) => getLabel(item)).join(', ')
    : undefined;

  return (
    <>
      {/* Measure container - invisible, renders all tags + children */}
      <Stack
        ref={measureContainerRef}
        direction="row"
        gap={`${gapPx}px`}
        sx={{
          position: 'absolute',
          visibility: 'hidden',
          pointerEvents: 'none',
          left: -9999,
          top: -9999,
          maxWidth,
          flexWrap: 'nowrap',
          flexDirection: isRTL ? 'row-reverse' : 'row',
        }}
        aria-hidden="true"
      >
        {items.map((item) => (
          <div key={getKey(item)} data-tag-item>
            {renderTag(item)}
          </div>
        ))}
        <div data-overflow-tag>
          <Tag label={`+${items.length}`} />
        </div>
        {children && (
          <div data-trailing-content style={{ flexShrink: 0 }}>
            {children}
          </div>
        )}
      </Stack>

      {/* Visible container - displays only visible tags + children */}
      <Stack
        ref={visibleContainerRef}
        direction="row"
        gap={`${gapPx}px`}
        sx={{
          flex: 1,
          minWidth: 0,
          maxWidth,
          overflow: 'hidden',
          flexWrap: 'nowrap',
          flexDirection: isRTL ? 'row-reverse' : 'row',
        }}
      >
        {displayItems.map((item) => (
          <div key={getKey(item)}>
            {renderTag(item)}
          </div>
        ))}

        {overflowCount > 0 && (
          <Tag
            label={`+${overflowCount}`}
            tooltipTitle={tooltipTitle}
            onClick={onTagCounterClick}
          />
        )}

        {children && (
          <div>
            {children}
          </div>
        )}
      </Stack>
    </>
  );
}

export default TagsOverflow;
