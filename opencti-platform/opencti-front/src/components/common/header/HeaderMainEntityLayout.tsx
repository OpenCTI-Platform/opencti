import React, { ReactNode } from 'react';
import Stack from '@mui/material/Stack';
import TitleMainEntity from '../typography/TitleMainEntity';
import { Tooltip } from '@mui/material';

interface HeaderMainEntityLayoutProps {
  title: string;
  hideTitle?: boolean;
  titleRight?: ReactNode;
  rightActions?: ReactNode;
  leftTags?: ReactNode;
  rightTags?: ReactNode;
  // should be removed when knowledge buttons is fixed
  hasPlaceholderTags?: boolean;
}

const TAGS_HEIGHT = 25;

const HeaderMainEntityLayout = ({
  title,
  hideTitle = false,
  titleRight,
  rightActions,
  leftTags,
  rightTags,
  hasPlaceholderTags = true,
}: HeaderMainEntityLayoutProps) => {
  const hasLeftTags = Boolean(leftTags);
  const hasRightTags = Boolean(rightTags);
  const hasBothTags = hasLeftTags && hasRightTags;

  return (
    <Stack gap={1} sx={{ marginBottom: 1 }}>
      {/* Title + TitleRight on left + Actions on right */}
      <Stack
        direction="row"
        justifyContent="space-between"
        gap={3}
      >
        <Stack
          direction="row"
          sx={{
            flex: 1,
            minWidth: 0,
          }}
          gap={1}
        >
          {/* Title */}
          {!hideTitle && (
            <Stack
              sx={{
                minWidth: 0,
                overflow: 'hidden',
              }}
            >
              <Tooltip title={title}>
                <span>
                  <TitleMainEntity
                    preserveCase
                    sx={{
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                    }}
                  >
                    {title}
                  </TitleMainEntity>
                </span>
              </Tooltip>
            </Stack>
          )}

          {/* Optional for display as in some headers */}
          {titleRight}
        </Stack>

        {/* Right actions */}
        <Stack
          direction="row"
          alignItems="center"
          gap={1}
        >
          {rightActions}
        </Stack>
      </Stack>

      {/* Second row */}
      <Stack
        direction="row"
        alignContent="center"
        justifyContent="space-between"
        gap={3}
        sx={{ height: hasPlaceholderTags ? TAGS_HEIGHT : 0 }}
      >
        <Stack
          direction="row"
          gap={1}
          sx={{
            flex: 1,
            minWidth: 0,
            maxWidth: hasBothTags ? '50%' : '100%',
            overflow: 'hidden',
          }}
        >
          {leftTags}
        </Stack>

        <Stack
          direction="row"
          alignItems="center"
          sx={{
            flex: 1,
            minWidth: 0,
            maxWidth: hasBothTags ? '50%' : '100%',
          }}
        >
          {rightTags}
        </Stack>
      </Stack>
    </Stack>
  );
};

export default HeaderMainEntityLayout;
