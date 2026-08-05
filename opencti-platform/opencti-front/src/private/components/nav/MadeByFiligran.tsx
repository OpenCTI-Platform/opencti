import React from 'react';
import { useFormatter } from '../../../components/i18n';
import logoFiligran from '../../../static/images/logo_filigran_full.svg';

/**
 * "Made by Filigran" signature, pinned to the bottom of the rail.
 *
 * Same technique as the OpenAEV pilot
 * (openaev-front/src/components/common/menu/navbar/MadeByFiligran.tsx):
 * geometry is expressed inline because the product has no Tailwind build — the
 * only utilities that exist at runtime are those the design system emits into
 * its own stylesheet, so a sizing class here would be silently inert. The
 * caption typography, on the other hand, uses design-system utilities: those
 * are published on purpose and keep the label aligned with the library.
 *
 * Collapsed, only the Filigran emblem remains, as in OpenAEV. The emblem is not
 * a separate asset: the wordmark SVG starts with it, so a 12px square box with
 * `object-fit: cover` and a left origin crops the lettering away.
 *
 * The row is not interactive, exactly like the component it replaces.
 */
const WORDMARK_HEIGHT = 12;

const MadeByFiligran: React.FC<{ collapsed: boolean }> = ({ collapsed }) => {
  const { t_i18n } = useFormatter();
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        // The row is our own container, spanning the rail's full width, so
        // centring lands exactly on the axis of the icons above (measured in
        // the running product). OpenAEV needs an extra 2px offset because it
        // hangs the signature on the library's own `NavbarItem`, whose content
        // box is inset by the 2px selected-row border.
        justifyContent: collapsed ? 'center' : 'flex-start',
        gap: 4,
        height: 36,
        paddingLeft: collapsed ? 0 : 16,
        paddingRight: collapsed ? 0 : 8,
      }}
    >
      {!collapsed && (
        <span className="text-default-secondary shrink-0 text-content-caption font-content-caption leading-content-caption tracking-content-caption">
          {t_i18n('Made by')}
        </span>
      )}
      <img
        alt="Filigran"
        src={logoFiligran}
        className="shrink-0"
        style={collapsed
          ? {
              width: WORDMARK_HEIGHT,
              height: WORDMARK_HEIGHT,
              objectFit: 'cover',
              objectPosition: 'left center',
              opacity: 0.8,
            }
          : {
              height: WORDMARK_HEIGHT,
              width: 'auto',
              opacity: 0.8,
            }}
      />
    </div>
  );
};

export default MadeByFiligran;
