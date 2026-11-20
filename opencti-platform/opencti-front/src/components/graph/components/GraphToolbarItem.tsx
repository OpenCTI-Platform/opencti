import React, { ReactNode, useId } from 'react';
import { Badge, IconButton, IconButtonProps, Menu, MenuContent, MenuTrigger, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
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
  onClick?: IconButtonProps['onClick'];
  /** Menu items the tool opens, in a menu anchored to it, instead of running an action. */
  menu?: ReactNode;
  disabled?: boolean;
  /** Why the tool is not available now; disables it and says so in its tooltip. */
  disabledReason?: string;
  /** What the tool does, under its name in the tooltip; the reason replaces it while the tool is disabled. */
  description?: string;
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
  menu,
  disabled,
  disabledReason,
  description,
  badge,
}: GraphToolbarItemProps) => {
  const { t_i18n } = useFormatter();
  const reasonId = useId();
  const isDisabled = disabled || !!disabledReason;
  const opensMenu = !!menu && !isDisabled;
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
  if (opensMenu) control = <MenuTrigger asChild>{control}</MenuTrigger>;
  if (isDisabled) {
    control = (
      // A disabled tool stays in the keyboard path of the toolbar, so that the reason can be read
      // (WAI-ARIA toolbar pattern); the library button has no focusable disabled state. Its own tab stop
      // serves outside the toolbar (the folded creation tools), the roving focus of the toolbar overrides it.
      // FDS-WORKAROUND #68: a disabled IconButton cannot trigger its own tooltip - see fds-migration/LIBRARY-FEEDBACK.md #68
      <span
        role="button"
        tabIndex={0}
        aria-label={title}
        aria-disabled
        aria-pressed={pressed}
        aria-keyshortcuts={shortcut}
        className="inline-flex rounded-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:ring-offset-focus focus-visible:ring-filigran-brand-primary"
      >
        {control}
        {disabledReason && <span id={reasonId} hidden>{disabledReason}</span>}
      </span>
    );
  }
  // The description is set on the trigger, which adds the tooltip's own while it is open.
  control = (
    <TooltipTrigger asChild aria-describedby={isDisabled && disabledReason ? reasonId : undefined}>
      {control}
    </TooltipTrigger>
  );
  if (badge) {
    // The badge wraps the trigger, never the reverse: it hands its props to its count bubble, which lets no
    // pointer or focus event through, and it adds its count to the description of the trigger.
    control = (
      <Badge content={badge} tone="brand" accessibleText={t_i18n('{count, plural, one {# in use} other {# in use}}', { values: { count: badge } })}>
        {control}
      </Badge>
    );
  }
  const item = (
    <Tooltip>
      {control}
      <TooltipContent side="top">
        {shortcut ? `${title} (${shortcut})` : title}
        {(isDisabled ? disabledReason : description) && (
          <>
            <br />
            {isDisabled ? disabledReason : description}
          </>
        )}
      </TooltipContent>
    </Tooltip>
  );
  if (!opensMenu) return item;
  return (
    <Menu modal={false}>
      {item}
      <MenuContent
        side="top"
        align="start"
        aria-label={title}
        style={{ maxHeight: 'min(60vh, var(--radix-dropdown-menu-content-available-height))', overflowY: 'auto' }}
      >
        {menu}
      </MenuContent>
    </Menu>
  );
};

export default GraphToolbarItem;
