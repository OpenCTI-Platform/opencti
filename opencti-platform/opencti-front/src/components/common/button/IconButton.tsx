import React from 'react';
import { IconButton as LibIconButton } from '@filigran/design-system';
import Button, { CustomButtonProps } from './Button';

/**
 * Same two axes as `Button`: the wrapper's `variant` is a PRIORITY, its
 * `intent`/`color` are the TONE. The library IconButton is NOT the library
 * Button: its tone axis has no `highlight`, so `ee` has no expression here and
 * a site using it keeps MUI. See fds-migration/LIBRARY-FEEDBACK.md.
 */
const LIB_PRIORITY = { primary: 'primary', secondary: 'secondary', tertiary: 'tertiary' } as const;
const LIB_TONE_FROM_INTENT = { default: 'default', destructive: 'destructive', ai: 'ia' } as const;
const LIB_TONE_FROM_COLOR = {
  default: 'default', primary: 'default', secondary: 'default',
  error: 'destructive', destructive: 'destructive', ai: 'ia',
} as const;

const IconButton: React.FC<Omit<CustomButtonProps, 'iconOnly'>> = (props) => {
  const {
    children, title, sx, classes, gradient, selected, component, to, href,
    variant, intent, color, size, disabled, keepMui, ...rest
  } = props as typeof props & {
    title?: string; classes?: unknown; gradient?: boolean; selected?: boolean;
    keepMui?: boolean;
  };
  const label = (props as { 'aria-label'?: string })['aria-label'] ?? title;

  // The delegate has always defaulted to the quiet, small control.
  /**
   * `color="secondary"` with no `variant` is MUI's bordered control. Reading it
   * as a tone alone would drop the border, so it becomes the secondary
   * PRIORITY -- which is where the border lives in the library.
   */
  const impliedPriority = color === 'secondary' && !variant ? 'secondary' : 'tertiary';
  const libPriority = variant ? LIB_PRIORITY[variant as keyof typeof LIB_PRIORITY] : impliedPriority;
  const libTone = color
    ? LIB_TONE_FROM_COLOR[color as keyof typeof LIB_TONE_FROM_COLOR]
    : LIB_TONE_FROM_INTENT[(intent ?? 'default') as keyof typeof LIB_TONE_FROM_INTENT];

  /**
   * A site keeps MUI whenever the library cannot carry its meaning: no
   * accessible name, MUI-only styling, or a tone/priority outside the tables
   * above (`ee`, `warn`, `success`, `extra`, or anything dynamic). Dropping the
   * tone silently would have cost these sites their signal.
   */
  /**
   * `asChild` REPLACES the child's content with the glyph, so a control whose
   * element must keep its own children cannot live there: `component="label"`
   * wraps a real `<input type="file">`, which the library would destroy. Those
   * keep MUI, where `ButtonBase` also gives the label the role and tab stop the
   * library path would not (WCAG 2.1.1).
   */
  const rendersAnchor = Boolean(to) || Boolean(href) || component === 'a';
  const isPolymorphic = Boolean(component || to || href);

  const canUseLibrary = Boolean(label)
    && Boolean(libPriority)
    && Boolean(libTone)
    && !sx && !classes && !gradient && !selected && !keepMui
    && (!isPolymorphic || rendersAnchor);

  if (canUseLibrary) {
    const libSize = size === 'default' ? 'md' : 'sm';
    const common = {
      priority: libPriority,
      variant: libTone,
      size: libSize as 'md' | 'sm',
      disabled: disabled as boolean | undefined,
      'aria-label': label as string,
      icon: children,
    };

    /**
     * An icon-only control that is really a LINK. It goes through the library
     * IconButton, not the library Button: the Button carries the horizontal
     * padding of a text label, which drew a 36x24 pill around a 20x20 glyph
     * instead of a square control. `rest` carries the site's own props --
     * `onClick`, `target`, `rel`, `data-testid` -- which the control needs.
     */
    if (rendersAnchor) {
      const Child = (component ?? 'a') as React.ElementType;
      // `disabled` is not an anchor attribute; the library drops the control's
      // own interactivity instead.
      const { disabled: _drop, ...anchorProps } = common;
      return (
        <LibIconButton asChild {...anchorProps}>
          <Child to={to} href={href} {...(rest as Record<string, unknown>)} />
        </LibIconButton>
      );
    }

    return (
      <LibIconButton
        // Same submit trap as Button: MUI defaulted to `type="button"`.
        type="button"
        {...common}
        {...(rest as React.ComponentPropsWithoutRef<'button'>)}
      />
    );
  }

  return (
    <Button
      variant="tertiary"
      size="small"
      {...(props as CustomButtonProps)}
      iconOnly
    />
  );
};

export default IconButton;
