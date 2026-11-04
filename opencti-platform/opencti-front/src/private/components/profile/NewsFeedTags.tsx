import { Chip, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { Stack } from '@mui/material';
import React, { FunctionComponent } from 'react';
import Tag from '../../../components/common/tag/Tag';
import useChipOverflow from '../integrations/catalog/components/card/usecases/useChipOverflow';

// Height of a design system chip: the row must be at least as tall, or the chips get cut.
const CHIP_HEIGHT = 24;

interface NewsFeedTagsProps {
  tags: readonly (string | null | undefined)[];
  lowercase?: boolean;
}

/**
 * Tags on a single line: the ones that do not fit are hidden behind a "+N" tag, its tooltip lists them.
 * The first tag is truncated when it is too long to leave room for the "+N" tag, so the latter is always visible.
 */
const NewsFeedTags: FunctionComponent<NewsFeedTagsProps> = ({ tags, lowercase = false }) => {
  const format = (tag: string) => (lowercase ? tag.toLowerCase() : tag);
  const tagValues = tags.filter(Boolean) as string[];
  const { containerRef, chipRefs, visibleCount, shouldTruncate } = useChipOverflow(tagValues);
  const hiddenCount = tagValues.length - visibleCount;

  return (
    <div
      ref={containerRef}
      style={{ display: 'flex', flexWrap: 'nowrap', alignItems: 'center', overflow: 'hidden', width: '100%', position: 'relative', gap: 4, height: CHIP_HEIGHT }}
    >
      {/* Hidden measurement row */}
      <Stack
        direction="row"
        sx={{
          position: 'absolute',
          visibility: 'hidden',
          gap: 0.5,
        }}
      >
        {tagValues.map((tag, index) => (
          <div
            key={tag}
            ref={(el) => {
              chipRefs.current[index] = el;
            }}
          >
            <Tag label={tag} />
          </div>
        ))}
      </Stack>

      {/* Visible tags + overflow tag in the same row */}
      {tagValues.slice(0, visibleCount).map((tag, index) => (
        // only the first tag shrinks (with an ellipsis): the others fit by construction
        <div key={tag} style={{ minWidth: 0, flexShrink: index === 0 ? 1 : 0, display: 'flex' }}>
          <Tag label={format(tag)} maxWidth="100%" />
        </div>
      ))}
      {shouldTruncate && hiddenCount > 0 && (
        <Tooltip>
          <TooltipTrigger asChild>
            {/* focusable so the hidden tags are reachable from the keyboard too */}
            {/* eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex */}
            <span style={{ flexShrink: 0, display: 'inline-flex' }} tabIndex={0}>
              <Chip label={`+${hiddenCount}`} />
            </span>
          </TooltipTrigger>
          <TooltipContent side="bottom" align="start">
            {tagValues.slice(visibleCount).map(format).join(', ')}
          </TooltipContent>
        </Tooltip>
      )}
    </div>
  );
};

export default NewsFeedTags;
