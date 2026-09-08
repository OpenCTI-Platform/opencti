import { Chip } from '@filigran/design-system';
import { Tooltip } from '@mui/material';
import React from 'react';

export interface TagProps {
  label?: string | number | null;
  color?: string | null;
  onClick?: (e: React.MouseEvent) => void;
  onDelete?: (e: React.MouseEvent) => void;
  /** Accessible name for the delete button. Defaults, in the library, to an
   *  untranslated `Remove ${label}` — pass a translated string. */
  deleteLabel?: string;
  /** `-1` inside a composite widget (a chip row in a select field owns its own
   *  focus order, so each chip must not add a Tab stop). */
  deleteTabIndex?: number;
  maxWidth?: number | string;
  icon?: React.ReactElement;
  tooltipTitle?: string;
  disableTooltip?: boolean;
  labelTextTransform?: 'capitalize' | 'uppercase' | 'lowercase' | 'none';
  className?: string;
  id?: string;
  disabled?: boolean;
  style?: React.CSSProperties;
  sx?: Record<string, unknown>;
  size?: 'small' | 'medium';
  variant?: 'filled' | 'outlined';
}

const Tag = ({
  label,
  color,
  onClick,
  onDelete,
  deleteLabel,
  deleteTabIndex,
  maxWidth = '100%',
  icon,
  tooltipTitle,
  disableTooltip = false,
  labelTextTransform = 'capitalize',
  className,
  id,
  disabled,
  sx,
  style,
}: TagProps) => {
  // `label` has always accepted a number or an element; the library types it as
  // a string, so it is flattened here rather than at 202 call sites.
  const text = typeof label === 'string' || typeof label === 'number' ? String(label) : '';
  const flatSx = Object.fromEntries(
    Object.entries(sx ?? {}).filter(([k, v]) => !k.includes('&') && typeof v !== 'object'),
  ) as React.CSSProperties;

  const chip = (
    <Chip
      id={id}
      label={text}
      color={color ?? undefined}
      startIcon={icon}
      onClick={onClick}
      // the library's handler takes no event; the wrapper's callers expect one
      onDelete={onDelete ? () => onDelete({} as React.MouseEvent) : undefined}
      deleteLabel={deleteLabel}
      deleteTabIndex={deleteTabIndex}
      className={className}
      disabled={disabled}
      style={{
        textTransform: labelTextTransform,
        maxWidth: typeof maxWidth === 'number' ? `${maxWidth}px` : maxWidth,
        ...flatSx,
        ...style,
      }}
    />
  );

  const addsSomething = tooltipTitle !== undefined && tooltipTitle !== text;
  if (disableTooltip || !addsSomething) {
    return chip;
  }

  return (
    // The Chip is the Tooltip's direct child on purpose: an intermediate <span> makes MUI label the wrapper AND
    // leaves the chip's own text matchable, so `getByLabel` resolves to two elements.
    <Tooltip title={tooltipTitle} placement="bottom-start">
      {chip}
    </Tooltip>
  );
};

export default Tag;
