import React from 'react';
import { useFormatter } from '../../../components/i18n';
import logoFiligran from '../../../static/images/logo_filigran_full.svg';

/** "Made by Filigran" signature, pinned to the bottom of the rail. */
const WORDMARK_HEIGHT = 12;

const MadeByFiligran: React.FC<{ collapsed: boolean }> = ({ collapsed }) => {
  const { t_i18n } = useFormatter();
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        // The row is our own container, spanning the rail's full width, so centring lands
        // exactly on the axis of the icons above (measured in the running product).
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
