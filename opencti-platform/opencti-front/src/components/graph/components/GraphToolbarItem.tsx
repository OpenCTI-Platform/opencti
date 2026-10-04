import React, { MouseEvent, ReactNode, useId } from 'react';
import { Badge, IconButton, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { useFormatter } from '../../i18n';

interface GraphToolbarItemProps {
  title: string;
  /** `secondary` marks a tool that is on; prefer `pressed` for a toggle. */
  color?: 'primary' | 'secondary';
  /** A toggle: announced as pressed or not, its label staying the same. */
  pressed?: boolean;
  /** Key or chord shown in the tooltip, for example `Shift+F`. */
  shortcut?: string;
  Icon: ReactNode;
  onClick: (event: MouseEvent<HTMLButtonElement>) => void;
  disabled?: boolean;
  /** Why the tool is not available now; disables it and says so in its tooltip. */
  disabledReason?: string;
  /** Number of filters or choices in use, drawn on the button. */
  badge?: number;
}

const GraphToolbarItem = ({
  title,
  color = 'primary',
  pressed,
  shortcut,
  Icon,
  onClick,
  disabled,
  disabledReason,
  badge,
}: GraphToolbarItemProps) => {
  const { t_i18n } = useFormatter();
  const reasonId = useId();
  const isDisabled = disabled || !!disabledReason;
  // The icon button announces `active` as pressed: a plain action leaves it unset.
  const active = pressed ?? (color === 'secondary' ? true : undefined);
  let control: ReactNode = (
    <IconButton
      priority="tertiary"
      aria-label={title}
      aria-keyshortcuts={shortcut}
      active={active}
      onClick={onClick}
      disabled={isDisabled}
      icon={Icon}
      // Disabled, the button is only drawn: its wrapper is the control, and opens the tooltip saying why.
      aria-hidden={isDisabled || undefined}
      style={isDisabled ? { pointerEvents: 'none' } : undefined}
    />
  );
  if (badge) {
    control = (
      <Badge content={badge} tone="brand" accessibleText={t_i18n('{count, plural, one {# in use} other {# in use}}', { values: { count: badge } })}>
        {control}
      </Badge>
    );
  }
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        {isDisabled ? (
          // A disabled tool stays in the keyboard path of the toolbar, so that the reason can be read
          // (WAI-ARIA toolbar pattern); the library button has no focusable disabled state.
          <span
            role="button"
            aria-label={title}
            aria-disabled
            aria-pressed={pressed}
            aria-keyshortcuts={shortcut}
            aria-describedby={disabledReason ? reasonId : undefined}
            className="inline-flex rounded-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:ring-offset-focus focus-visible:ring-filigran-brand-primary"
          >
            {control}
            {disabledReason && <span id={reasonId} hidden>{disabledReason}</span>}
          </span>
        ) : control}
      </TooltipTrigger>
      <TooltipContent side="top">
        {shortcut ? `${title} (${shortcut})` : title}
        {isDisabled && disabledReason && (
          <>
            <br />
            {disabledReason}
          </>
        )}
      </TooltipContent>
    </Tooltip>
  );
};

export default GraphToolbarItem;
