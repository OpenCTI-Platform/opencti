import React from 'react';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import { useFormatter } from '../../../../../../components/i18n';
import { OaevLogo } from '../../../../../../static/images/logo_oaev';
import useGranted, { SETTINGS_SETPARAMETERS } from '../../../../../../utils/hooks/useGranted';
import useXtmCounterpart, { XtmCounterpartKind } from '../core/useXtmCounterparts';
import { useCompactPivot, withTooltip, XTM_CONNECT_DOC_URL } from '../core/xtmPivot';

interface OpenAevPivotProps {
  kind: XtmCounterpartKind;
  // The natural key both platforms share: hostname, MITRE id, CVE id or STIX id.
  counterpartKey: string | null | undefined;
}

/**
 * Hero action of an object OpenAEV can also hold, rendered as the framed outlined text button of
 * the header toolbar (the same control as "Create Relationship", and the same language as OpenAEV's
 * "Open in OpenCTI"): "Open in OpenAEV" on a match, a disabled "Not in OpenAEV" without one, and
 * "Connect OpenAEV" when OpenAEV is not connected (disabled, with a read-only hint, for a user who
 * cannot configure the platform). Never an unframed icon. Silent while loading. Below 1280 px the
 * same states render as the framed icon button of the toolbar (XTM_PIVOT_COMPACT_QUERY).
 */
const OpenAevPivot: React.FC<OpenAevPivotProps> = ({ kind, counterpartKey }) => {
  const { t_i18n } = useFormatter();
  const canConfigure = useGranted([SETTINGS_SETPARAMETERS]);
  const state = useXtmCounterpart('openaev', kind, counterpartKey);
  const compact = useCompactPivot();

  if (compact) {
    switch (state.status) {
      case 'match':
        return (
          <IconButton
            variant="secondary"
            size="default"
            href={state.counterpart.object_url}
            target="_blank"
            rel="noopener noreferrer"
            aria-label={t_i18n('Open in OpenAEV')}
            tooltip={state.counterpart.object_name
              ? `${t_i18n('Open in OpenAEV')}: ${state.counterpart.object_name}`
              : t_i18n('Open in OpenAEV')}
            data-testid="openaev-pivot"
          >
            <OaevLogo />
          </IconButton>
        );
      case 'no_match':
        return (
          <IconButton variant="secondary" size="default" disabled aria-label={t_i18n('Not in OpenAEV')} tooltip={t_i18n('Not in OpenAEV')} data-testid="openaev-pivot">
            <OaevLogo />
          </IconButton>
        );
      case 'not_connected':
        return canConfigure
          ? (
              <IconButton
                variant="secondary"
                size="default"
                href={XTM_CONNECT_DOC_URL}
                target="_blank"
                rel="noopener noreferrer"
                aria-label={t_i18n('Connect OpenAEV')}
                tooltip={t_i18n('Connect OpenAEV to pivot to this object and test it')}
                data-testid="openaev-pivot"
              >
                <OaevLogo />
              </IconButton>
            )
          : (
              <IconButton
                variant="secondary"
                size="default"
                disabled
                aria-label={t_i18n('OpenAEV is not connected')}
                tooltip={t_i18n('OpenAEV is not connected: ask an administrator to connect it')}
                data-testid="openaev-pivot"
              >
                <OaevLogo />
              </IconButton>
            );
      default:
        return null;
    }
  }

  switch (state.status) {
    case 'match':
      return withTooltip(
        state.counterpart.object_name
          ? `${t_i18n('Open in OpenAEV')}: ${state.counterpart.object_name}`
          : t_i18n('Open in OpenAEV'),
        <Button
          variant="secondary"
          startIcon={<OaevLogo />}
          href={state.counterpart.object_url}
          target="_blank"
          rel="noopener noreferrer"
          data-testid="openaev-pivot"
        >
          {t_i18n('Open in OpenAEV')}
        </Button>,
      );
    case 'no_match':
      return withTooltip(
        t_i18n('Not in OpenAEV'),
        <Button variant="secondary" startIcon={<OaevLogo />} disabled data-testid="openaev-pivot">
          {t_i18n('Not in OpenAEV')}
        </Button>,
      );
    case 'not_connected':
      return canConfigure
        ? withTooltip(
            t_i18n('Connect OpenAEV to pivot to this object and test it'),
            <Button
              variant="secondary"
              startIcon={<OaevLogo />}
              href={XTM_CONNECT_DOC_URL}
              target="_blank"
              rel="noopener noreferrer"
              data-testid="openaev-pivot"
            >
              {t_i18n('Connect OpenAEV')}
            </Button>,
          )
        : withTooltip(
            t_i18n('OpenAEV is not connected: ask an administrator to connect it'),
            <Button
              variant="secondary"
              startIcon={<OaevLogo />}
              disabled
              aria-label={t_i18n('OpenAEV is not connected')}
              data-testid="openaev-pivot"
            >
              {t_i18n('Connect OpenAEV')}
            </Button>,
          );
    default:
      return null;
  }
};

export default OpenAevPivot;
