import React from 'react';
import { IconButton as LibIconButton } from '@filigran/design-system';
import Button, { CustomButtonProps } from './Button';

/**
 * The library `IconButton` REQUIRES an accessible name -- an icon-only control
 * has no visible text to fall back on. 83 of the 358 sites carry neither
 * `aria-label` nor `title`, so the name is decided per site at runtime: a site
 * that has one converts, a site that has none keeps the MUI path rather than
 * ship an invented label. Those 83 are listed in the PR body; giving them real
 * names is product work, not a mechanical rename.
 */
const IconButton: React.FC<Omit<CustomButtonProps, 'iconOnly'>> = (props) => {
  const { children, title, sx, classes, gradient, selected, component, to, href, ...rest } = props as
    typeof props & { title?: string; classes?: unknown; gradient?: boolean; selected?: boolean };
  const label = (props as { 'aria-label'?: string })['aria-label'] ?? title;
  const canUseLibrary = Boolean(label) && !sx && !classes && !gradient && !selected && !component && !to && !href;

  if (canUseLibrary) {
    const { size, variant: _variant, intent: _intent, color: _color, ...domProps } = rest as Record<string, unknown>;
    return (
      <LibIconButton
        // Same submit trap as Button: MUI defaulted to `type="button"`.
        type="button"
        // The delegate has always defaulted to the quiet, small control.
        priority="tertiary"
        size={size === 'default' ? 'md' : 'sm'}
        {...(domProps as React.ComponentPropsWithoutRef<'button'>)}
        aria-label={label as string}
        icon={children}
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
