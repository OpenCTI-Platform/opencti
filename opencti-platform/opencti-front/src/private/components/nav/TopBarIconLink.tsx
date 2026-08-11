import { iconButtonVariants } from '@filigran/design-system';
import React, { FunctionComponent, ReactNode } from 'react';
import { Link } from 'react-router-dom';

// FDS-WORKAROUND #13: icon button that is really a link, library variants reused — remove when `IconButton` accepts `asChild` — see fds-migration/LIBRARY-FEEDBACK.md #13

/** The background `IconButton` paints for `active`, as the library's own token. */
const SELECTED_BACKGROUND = 'var(--color-filigran-brand-primary-transparency)';

/** The glyph colour `IconButton` resolves; `text-inherit` alone would take the bar's. */
const GLYPH_COLOR = 'var(--color-filigran-brand-primary)';

interface TopBarIconLinkProps {
  /** Required accessible label — icon-only controls have no visible text. */
  'aria-label': string;
  /** The glyph. Wrapped in an aria-hidden span, exactly as IconButton does. */
  icon: ReactNode;
  /** Internal router route. */
  to: string;
  /** Current-page state, mirroring IconButton's `active`. */
  active?: boolean;
  id?: string;
}

/**
 * Same technique as the OpenAEV Header pilot
 * (openaev-front/src/admin/components/nav/TopBarIconLink.tsx).
 */
const TopBarIconLink: FunctionComponent<TopBarIconLinkProps> = ({
  'aria-label': ariaLabel,
  icon,
  to,
  active,
  id,
}) => {
  // `tertiary` is the bar's anatomy; the default `primary` is a FILLED brand button.
  const classes = iconButtonVariants({ priority: 'tertiary' });

  // FDS-WORKAROUND #16: colour and selected background inline, layered utilities lose here — see fds-migration/LIBRARY-FEEDBACK.md #16
  const style = {
    color: GLYPH_COLOR,
    ...(active && { backgroundColor: SELECTED_BACKGROUND }),
  };

  return (
    <Link
      id={id}
      aria-label={ariaLabel}
      className={classes}
      style={style}
      to={to}
      {...(active !== undefined && { 'aria-current': active ? 'page' : undefined })}
    >
      {/* `aria-hidden` on the glyph, label on the control, as IconButton does. */}
      <span className="inline-flex shrink-0" aria-hidden="true">{icon}</span>
    </Link>
  );
};

export default TopBarIconLink;
