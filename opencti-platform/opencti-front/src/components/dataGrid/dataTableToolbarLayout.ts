import type { CSSProperties } from 'react';

// Layout of the DataTable toolbar row: filters on the left, pagination, view toggles, header buttons and the
// create button on the right. The row wraps and the left group may shrink, so on a narrow viewport (1080 px and
// below) the right-hand group moves to a second line as one block instead of pushing the page into a horizontal
// scroll and cutting the create button.

export const dataTableToolbarRowStyle = (gap: string): CSSProperties => ({
  display: 'flex',
  flexWrap: 'wrap',
  justifyContent: 'space-between',
  // `alignItems: center`: without it the row defaults to `stretch`, so the left group (which centres its own
  // children) and the right group of 36px toggles resolve to different centre lines.
  alignItems: 'center',
  flex: 1,
  minWidth: 0,
  gap,
});

export const dataTableToolbarLeftGroupStyle = (gap: string): CSSProperties => ({
  display: 'flex',
  alignItems: 'center',
  minWidth: 0,
  gap,
});

export const dataTableToolbarRightGroupStyle = (gap: string): CSSProperties => ({
  display: 'flex',
  gap,
  flexShrink: 0,
  // Keeps the group right-aligned when it wraps onto its own line.
  marginLeft: 'auto',
});
