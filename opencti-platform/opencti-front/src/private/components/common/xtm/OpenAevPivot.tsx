import React from 'react';
import IconButton from '@common/button/IconButton';
import { useFormatter } from '../../../../components/i18n';
import { OaevLogo } from '../../../../static/images/logo_oaev';
import useGranted, { SETTINGS_SETPARAMETERS } from '../../../../utils/hooks/useGranted';
import useXtmCounterpart, { XtmCounterpartKind } from './useXtmCounterparts';

// The OpenAEV connection of OpenCTI lives in its configuration (xtm:openaev_url, xtm:openaev_token).
export const OPENAEV_CONNECT_DOC_URL = 'https://docs.opencti.io/latest/deployment/configuration/#xtm-suite';

interface OpenAevPivotProps {
  kind: XtmCounterpartKind;
  // The natural key both platforms share: hostname, MITRE id, CVE id or STIX id.
  counterpartKey: string | null | undefined;
}

/**
 * Hero action of an object OpenAEV can also hold: "Open in OpenAEV" on a match, a muted
 * "Not in OpenAEV" without one, and the "Connect OpenAEV" call to action when OpenAEV is not
 * connected (a read-only hint for a user who cannot configure the platform). Silent while loading.
 */
const OpenAevPivot: React.FC<OpenAevPivotProps> = ({ kind, counterpartKey }) => {
  const { t_i18n } = useFormatter();
  const canConfigure = useGranted([SETTINGS_SETPARAMETERS]);
  const state = useXtmCounterpart('openaev', kind, counterpartKey);

  switch (state.status) {
    case 'match':
      return (
        <IconButton
          href={state.counterpart.object_url}
          target="_blank"
          rel="noopener noreferrer"
          aria-label={t_i18n('Open in OpenAEV')}
          tooltip={state.counterpart.object_name
            ? `${t_i18n('Open in OpenAEV')}: ${state.counterpart.object_name}`
            : t_i18n('Open in OpenAEV')}
        >
          <OaevLogo />
        </IconButton>
      );
    case 'no_match':
      return (
        <IconButton disabled aria-label={t_i18n('Not in OpenAEV')} tooltip={t_i18n('Not in OpenAEV')}>
          <OaevLogo />
        </IconButton>
      );
    case 'not_connected':
      return canConfigure ? (
        <IconButton
          href={OPENAEV_CONNECT_DOC_URL}
          target="_blank"
          rel="noopener noreferrer"
          aria-label={t_i18n('Connect OpenAEV')}
          tooltip={t_i18n('Connect OpenAEV to pivot to this object and test it')}
        >
          <OaevLogo />
        </IconButton>
      ) : (
        <IconButton
          disabled
          aria-label={t_i18n('OpenAEV is not connected')}
          tooltip={t_i18n('OpenAEV is not connected: ask an administrator to connect it')}
        >
          <OaevLogo />
        </IconButton>
      );
    default:
      return null;
  }
};

export default OpenAevPivot;
