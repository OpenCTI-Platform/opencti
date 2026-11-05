import React from 'react';
import { IconButton as LibIconButton, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import Button, { CustomButtonProps } from './Button';

/**
 * `variant` is a PRIORITY, `intent`/`color` the TONE. This tone axis has no
 * `highlight`, so `ee` has no expression here and such a site keeps MUI.
 * See fds-migration/LIBRARY-FEEDBACK.md.
 */
const LIB_PRIORITY = { primary: 'primary', secondary: 'secondary', tertiary: 'tertiary' } as const;
const LIB_TONE_FROM_INTENT = { default: 'default', destructive: 'destructive', ai: 'ia' } as const;
const LIB_TONE_FROM_COLOR = {
  default: 'default', primary: 'default', secondary: 'default',
  error: 'destructive', destructive: 'destructive', ai: 'ia',
} as const;

type IconButtonControlProps = Omit<CustomButtonProps, 'iconOnly'>;

export type IconButtonProps = IconButtonControlProps & {
  /**
   * Shown on hover and keyboard focus. A string tooltip also names the button when it has neither
   * `aria-label` nor `title`.
   */
  tooltip?: React.ReactNode;
};

/**
 * The icon-only control itself, from the library when its props allow it, from MUI otherwise.
 */
const IconButtonControl: React.FC<IconButtonControlProps> = (props) => {
  const {
    children, title, sx, classes, gradient, selected, component, to, href,
    variant, intent, color, size, disabled, keepMui, ...rest
  } = props as typeof props & {
    title?: string; classes?: unknown; gradient?: boolean; selected?: boolean;
    keepMui?: boolean;
  };
  const label = (props as { 'aria-label'?: string })['aria-label'] ?? title;

  const libPriority = variant ? LIB_PRIORITY[variant as keyof typeof LIB_PRIORITY] : 'tertiary';
  const libTone = color
    ? LIB_TONE_FROM_COLOR[color as keyof typeof LIB_TONE_FROM_COLOR]
    : LIB_TONE_FROM_INTENT[(intent ?? 'default') as keyof typeof LIB_TONE_FROM_INTENT];

  /**
   * `asChild` REPLACES the child's content with the glyph, so a control whose element must keep its own children
   * cannot live there: `component="label"` wraps a real `<input type="file">`, which the library would destroy.
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

/**
 * Icon-only button, with an optional tooltip.
 * The tooltip is anchored on a wrapping span rather than on the control: the control does not forward
 * its ref, and a disabled button receives no pointer events, so its tooltip would never show.
 */
const IconButton: React.FC<IconButtonProps> = ({
  tooltip,
  ...props
}) => {
  const { title } = props as typeof props & { title?: string };
  const hasLabel = Boolean((props as { 'aria-label'?: string })['aria-label'] ?? title);
  const controlProps = !hasLabel && typeof tooltip === 'string'
    ? { ...props, 'aria-label': tooltip }
    : props;

  if (!tooltip) {
    return <IconButtonControl {...controlProps} />;
  }

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span style={{ display: 'inline-flex' }}>
          <IconButtonControl {...controlProps} />
        </span>
      </TooltipTrigger>
      <TooltipContent>
        {tooltip}
      </TooltipContent>
    </Tooltip>
  );
};

export default IconButton;
