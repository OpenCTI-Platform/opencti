import { Chip } from '@filigran/design-system';
import { Tooltip } from '@mui/material';
import React from 'react';

export interface TagProps {
  /**
   * Text only. The library Chip types its label as a string, so a rich label
   * cannot survive here -- it used to be flattened to an empty chip. A site
   * that needs an element stays on MUI.
   */
  label?: string | number | null;
  /** Free colour from the data (a label or marking hex). The library bounds it. */
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
  /**
   * Legacy MUI escape hatch. Flat CSS keys are forwarded as `style`; nested
   * selectors (`&:hover`, `& .MuiChip-label`) are dropped, because they
   * addressed MUI's internals which no longer exist. Colour overrides that
   * used to live here are now the library's own `color` bounding.
   */
  sx?: Record<string, unknown>;
  /** MUI-only axes with no library equivalent; accepted so call sites still type-check. */
  size?: 'small' | 'medium';
  variant?: 'filled' | 'outlined';
}

// The library has no case axis, so the wrapper keeps its own. Written as an
// inline style rather than a utility class: the product consumes the library's
// PREBUILT css and does not run Tailwind over its own source, so a utility
// named here would simply not exist. 22 call sites rely on this, and the
// default stays `capitalize`.

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

  if (disableTooltip) {
    return chip;
  }

  return (
    // The Chip is the Tooltip's direct child on purpose: an intermediate
    // <span> makes MUI label the wrapper AND leaves the chip's own text
    // matchable, so `getByLabel` resolves to two elements. The library Chip
    // forwards its ref, so Tooltip can anchor on it directly.
    <Tooltip title={tooltipTitle ?? text} placement="bottom-start">
      {chip}
    </Tooltip>
  );
};

export default Tag;
