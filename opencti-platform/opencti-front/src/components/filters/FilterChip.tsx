import CancelIcon from '@mui/icons-material/Cancel';
import Box from '@mui/material/Box';
import { ChipOwnProps } from '@mui/material/Chip/Chip';
import { Theme, useTheme } from '@mui/material/styles';
import { CSSProperties, forwardRef, PropsWithChildren } from 'react';
import { FILTER_LINE_ITEM_HEIGHT } from '../../utils/filters/filtersUtils';
import { useFormatter } from '../i18n';

/** Beyond this the label ellipsises: a chip must never push the filter line into a scroll. */
const FILTER_CHIP_LABEL_MAX_WIDTH = 400;

export interface FilterChipProps {
  /** Outlined marks a filter the user started but has not given a value yet. */
  variant: 'filled' | 'outlined';
  /**
   * Tells apart the several filter sets displayed side by side (a widget shows the entity
   * filters, the source filters and the target filters on the same screen). Typed after MUI's
   * chip colors because the whole filter area — FilterValues, WidgetSavedFilterChips,
   * WidgetFilters — passes that same union around.
   */
  color?: ChipOwnProps['color'];
  /** Darker background, for the colors whose main tone makes the label unreadable. */
  darkenBackground?: boolean;
  /** Non-interactive: the last remaining filter of a list that requires one. */
  disabled?: boolean;
  /** Absent when the filter may not be removed (read-only line, or a restricted filter key). */
  onDelete?: () => void;
  style?: CSSProperties;
}

const getPaletteTone = (theme: Theme, color?: ChipOwnProps['color']) => {
  if (!color || color === 'default') return undefined;
  return theme.palette[color];
};

/**
 * The box of one applied filter in the filter line.
 *
 * Deliberately NOT a design-system `Chip`, and not a MUI one either: a chip carries a text
 * label, whereas what sits here is a small composition where several parts are their own
 * target — the filter key opens the value popover, the and/or switch between two values
 * toggles that filter's mode, each value carries its own tooltip. This component owns the box
 * (tone, outline, ellipsis, delete affordance) and nothing of what is inside it, which the
 * caller composes as `children`.
 */
const FilterChip = forwardRef<HTMLDivElement, PropsWithChildren<FilterChipProps>>(({
  variant,
  color,
  darkenBackground = false,
  disabled = false,
  onDelete,
  style,
  children,
}, ref) => {
  const theme = useTheme();
  const { t_i18n } = useFormatter();
  const tone = getPaletteTone(theme, color);

  const filledBackground = tone
    ? (darkenBackground ? tone.dark : tone.main)
    : theme.palette.action.selected;
  const filledForeground = tone ? tone.contrastText : theme.palette.text.primary;

  return (
    <Box
      ref={ref}
      // MUI's Chip (what this replaces) turns its root into a ButtonBase as soon as `onDelete`
      // is set, which is how the whole key+values line surfaced as a single accessible button.
      // Kept here so `getByRole('button', { name: 'Key = Value' })` still matches the chip as
      // a whole, not just the key part that owns its own nested button.
      role={onDelete ? 'button' : undefined}
      tabIndex={onDelete ? 0 : undefined}
      sx={{
        display: 'inline-flex',
        alignItems: 'center',
        maxWidth: '100%',
        borderRadius: 1,
        paddingInline: 1,
        gap: 0.5,
        height: FILTER_LINE_ITEM_HEIGHT,
        boxSizing: 'border-box',
        // An outlined chip keeps the tone on the text and the border only: it is how a filter
        // still waiting for a value reads as unfinished at a glance.
        backgroundColor: variant === 'filled' ? filledBackground : 'transparent',
        color: variant === 'filled' ? filledForeground : (tone?.main ?? theme.palette.text.primary),
        border: variant === 'outlined' ? `1px solid ${tone?.main ?? theme.palette.divider}` : 'none',
        opacity: disabled ? theme.palette.action.disabledOpacity : 1,
        pointerEvents: disabled ? 'none' : undefined,
        overflow: 'hidden',
        ...style,
      }}
    >
      <Box
        sx={{
          display: 'flex',
          alignItems: 'center',
          gap: 0.5,
          minWidth: 0,
          maxWidth: FILTER_CHIP_LABEL_MAX_WIDTH,
          whiteSpace: 'nowrap',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
        }}
      >
        {children}
      </Box>
      {onDelete && (
        <Box
          component="button"
          type="button"
          aria-label={t_i18n('Remove')}
          onClick={onDelete}
          sx={{
            display: 'flex',
            alignItems: 'center',
            padding: 0,
            border: 'none',
            background: 'none',
            cursor: 'pointer',
            color: 'inherit',
            opacity: 0.7,
            '&:hover': { opacity: 1 },
          }}
        >
          <CancelIcon fontSize="small" />
        </Box>
      )}
    </Box>
  );
});

FilterChip.displayName = 'FilterChip';

export default FilterChip;
