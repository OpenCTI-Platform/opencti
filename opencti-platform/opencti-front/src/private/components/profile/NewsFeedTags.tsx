import { Stack } from '@mui/material';
import React, { FunctionComponent } from 'react';
import Tag from '../../../components/common/tag/Tag';
import useChipOverflow from '../integrations/catalog/components/card/usecases/useChipOverflow';

interface NewsFeedTagsProps {
  tags: readonly (string | null | undefined)[];
  lowercase?: boolean;
}

/**
 * Tags on a single line: the ones that do not fit are hidden behind a "+N" tag, its tooltip lists them.
 */
const NewsFeedTags: FunctionComponent<NewsFeedTagsProps> = ({ tags, lowercase = false }) => {
  const format = (tag: string) => (lowercase ? tag.toLowerCase() : tag);
  const tagValues = tags.filter(Boolean) as string[];
  const { containerRef, chipRefs, visibleCount, shouldTruncate } = useChipOverflow(tagValues);
  const hiddenCount = tagValues.length - visibleCount;

  return (
    <div
      ref={containerRef}
      style={{ display: 'flex', flexWrap: 'nowrap', alignItems: 'center', overflow: 'hidden', width: '100%', position: 'relative', gap: 4, height: 20 }}
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
      <Stack
        direction="row"
        sx={{
          gap: 0.5,
          overflow: 'hidden',
          alignItems: 'center',
        }}
      >
        {tagValues.slice(0, visibleCount).map((tag) => (
          <Tag key={tag} label={format(tag)} />
        ))}
        {shouldTruncate && hiddenCount > 0 && (
          <Tag
            label={`+${hiddenCount}`}
            tooltipTitle={tagValues.slice(visibleCount).map(format).join(', ')}
            sx={{ flexShrink: 0, width: 'fit-content' }}
          />
        )}
      </Stack>
    </div>
  );
};

export default NewsFeedTags;
