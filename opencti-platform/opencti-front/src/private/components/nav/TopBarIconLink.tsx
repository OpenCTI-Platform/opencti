import { Badge, iconButtonVariants } from '@filigran/design-system';
import React, { ComponentPropsWithoutRef, ReactNode } from 'react';
import { Link } from 'react-router-dom';

// FDS-WORKAROUND #13: icon button that is really a link, library variants reused — remove when `IconButton` accepts `asChild` — see fds-migration/LIBRARY-FEEDBACK.md #13

/** The background `IconButton` paints for `active`, as the library's own token. */
const SELECTED_BACKGROUND = 'var(--color-filigran-brand-primary-transparency-10)';

/** The glyph colour `IconButton` resolves; `text-inherit` alone would take the bar's. */
const GLYPH_COLOR = 'var(--color-filigran-brand-primary)';

/**
 * The library `Badge`, wrapping the CONTROL. It marks the link, not the glyph: the glyph lives
 * in an `aria-hidden` span, so a badge nested in there is outside the accessibility tree and
 * its `aria-describedby` lands on a node no screen reader ever reaches.
 */
interface TopBarIconLinkBadge {
  /** The total, announced in full even when the visual reduces to a dot. */
  content: number;
  /** Reduced rendering — "there is something, do not show how much". */
  dot?: boolean;
  /** Not mounted at all when there is nothing to mark. */
  invisible?: boolean;
  /** Becomes the LINK's accessible DESCRIPTION; its name is left untouched. */
  accessibleText: string;
}

interface TopBarIconLinkProps extends Omit<ComponentPropsWithoutRef<typeof Link>, 'to' | 'children'> {
  /** Required accessible label — icon-only controls have no visible text. */
  'aria-label': string;
  /** The glyph. Wrapped in an aria-hidden span, exactly as IconButton does. */
  icon: ReactNode;
  to: string;
  /** Current-page state, mirroring IconButton's `active`. */
  active?: boolean;
  id?: string;
  /** Optional unread marker, painted around the whole control. */
  badge?: TopBarIconLinkBadge;
}

/** Same technique as the OpenAEV Header pilot (openaev- front/src/admin/components/nav/TopBarIconLink.tsx). */
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
  // `tertiary` is the bar's anatomy; the default `primary` is a FILLED brand button.
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
      {/* `aria-hidden` on the glyph, label on the control, as IconButton does. */}
      <span className="inline-flex shrink-0" aria-hidden="true">{icon}</span>
    </Link>
  );

  // `Badge` clones `aria-describedby` onto the single element it is given, so
  // the element it is given has to be the anchor itself.
  return badge ? <Badge {...badge}>{link}</Badge> : link;
});

TopBarIconLink.displayName = 'TopBarIconLink';

export default TopBarIconLink;
