import { Badge, iconButtonVariants } from '@filigran/design-system';
import React, { ComponentPropsWithoutRef, ReactNode } from 'react';
import { Link } from 'react-router-dom';

// FDS-WORKAROUND #13: icon button that is really a link, library variants reused — remove when `IconButton` accepts `asChild` — see fds-migration/LIBRARY-FEEDBACK.md #13

const SELECTED_BACKGROUND = 'var(--color-filigran-brand-primary-transparency-10)';

const GLYPH_COLOR = 'var(--color-filigran-brand-primary)';

interface TopBarIconLinkBadge {
  content: number;
  dot?: boolean;
  invisible?: boolean;
  accessibleText: string;
}

interface TopBarIconLinkProps extends Omit<ComponentPropsWithoutRef<typeof Link>, 'to' | 'children'> {
  'aria-label': string;
  icon: ReactNode;
  to: string;
  active?: boolean;
  id?: string;
  badge?: TopBarIconLinkBadge;
}

const TopBarIconLink = React.forwardRef<HTMLAnchorElement, TopBarIconLinkProps>(({
  'aria-label': ariaLabel,
  icon,
  to,
  active,
  id,
  badge,
  // Merged, never spread: an incoming `className` — including the `undefined` one a cloning parent passes — would
  // otherwise replace the library variant wholesale and the control would collapse to its glyph.
  className,
  style: incomingStyle,
  ...rest
}, ref) => {
  const classes = iconButtonVariants({ priority: 'tertiary' });

  // FDS-WORKAROUND #16: colour and selected background inline, layered utilities lose here — see fds-migration/LIBRARY-FEEDBACK.md #16
  const style = {
    color: GLYPH_COLOR,
    ...(active && { backgroundColor: SELECTED_BACKGROUND }),
    ...incomingStyle,
  };

  const link = (
    <Link
      ref={ref}
      id={id}
      aria-label={ariaLabel}
      className={[classes, className].filter(Boolean).join(' ')}
      style={style}
      to={to}
      {...(active !== undefined && { 'aria-current': active ? 'page' : undefined })}
      {...rest}
    >
      <span className="inline-flex shrink-0" aria-hidden="true">{icon}</span>
    </Link>
  );

  // `Badge` clones `aria-describedby` onto the single element it is given, so
  // the element it is given has to be the anchor itself.
  return badge ? <Badge {...badge}>{link}</Badge> : link;
});

TopBarIconLink.displayName = 'TopBarIconLink';

export default TopBarIconLink;
