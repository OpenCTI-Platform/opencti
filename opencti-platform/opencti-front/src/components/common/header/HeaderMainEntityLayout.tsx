import React, { ReactNode } from 'react';
import Stack from '@mui/material/Stack';
import TitleMainEntity from '../typography/TitleMainEntity';
import { Tooltip } from '@mui/material';

interface HeaderMainEntityLayoutProps {
  title: string;
  isNestedHeader?: boolean;
  titleRight?: ReactNode;
  rightActions?: ReactNode;
  leftTags?: ReactNode;
  rightTags?: ReactNode;
}

const HeaderMainEntityLayout = ({
  title,
  isNestedHeader = false,
  titleRight,
  rightActions,
  leftTags,
  rightTags,
}: HeaderMainEntityLayoutProps) => {
  const hasLeftTags = Boolean(leftTags);
  const hasRightTags = Boolean(rightTags);
  const hasBothTags = hasLeftTags && hasRightTags;
  const hasTagsRow = !isNestedHeader && (hasLeftTags || hasRightTags);

  return (
    <Stack
      sx={{
        gap: 1,
        marginBottom: 0,
      }}
    >
      {/* Title + TitleRight on left + Actions on right */}
      <Stack
        direction="row"
        sx={{
          justifyContent: 'space-between',
          gap: 3,
        }}
      >
        <Stack
          direction="row"
          sx={{
            alignItems: 'center',
            gap: 1,
            flex: 1,
            minWidth: 0,
          }}
        >
          {/* Title */}
          {!isNestedHeader && (
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
          sx={{
            alignItems: 'center',
            gap: 1,
          }}
        >
          {rightActions}
        </Stack>
      </Stack>

      {/* Second row */}
      {hasTagsRow
        && (
          <Stack
            direction="row"
            sx={{
              alignContent: 'center',
              justifyContent: 'space-between',
              gap: 3,
            }}
          >
            <Stack
              direction="row"
              sx={{
                gap: 1,
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
              sx={{
                alignItems: 'center',
                flex: 1,
                minWidth: 0,
                maxWidth: hasBothTags ? '50%' : '100%',
              }}
            >
              {rightTags}
            </Stack>
          </Stack>
        )}
    </Stack>
  );
};

export default HeaderMainEntityLayout;
