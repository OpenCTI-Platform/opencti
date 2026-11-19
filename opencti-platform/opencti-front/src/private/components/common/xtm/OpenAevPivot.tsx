import React, { useSyncExternalStore } from 'react';
import { Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import Button from '@common/button/Button';
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

// Below this viewport width the header has no room for a text button beside a long title and the
// "Display as" selector (the title was clipped to its first letter at 1080 px): the pivot becomes
// the framed icon button of its toolbar siblings, named by its aria-label and its tooltip.
export const OPENAEV_PIVOT_COMPACT_QUERY = '(max-width: 1279.98px)';

const subscribeCompact = (onChange: () => void) => {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return () => {};
  const query = window.matchMedia(OPENAEV_PIVOT_COMPACT_QUERY);
  query.addEventListener('change', onChange);
  return () => query.removeEventListener('change', onChange);
};
const readCompact = () => typeof window !== 'undefined'
  && typeof window.matchMedia === 'function'
  && window.matchMedia(OPENAEV_PIVOT_COMPACT_QUERY).matches;
export const useCompactPivot = () => useSyncExternalStore(subscribeCompact, readCompact, () => false);

// A tooltip on a wrapping span: a disabled button receives no pointer events, so a tooltip anchored
// on the control itself would never show.
export const withTooltip = (title: string, control: React.ReactElement) => (
  <Tooltip>
    <TooltipTrigger asChild>
      <span style={{ display: 'inline-flex' }}>{control}</span>
    </TooltipTrigger>
    <TooltipContent>{title}</TooltipContent>
  </Tooltip>
);

/**
 * Hero action of an object OpenAEV can also hold, rendered as the framed outlined text button of
 * the header toolbar (the same control as "Create Relationship", and the same language as OpenAEV's
 * "Open in OpenCTI"): "Open in OpenAEV" on a match, a disabled "Not in OpenAEV" without one, and
 * "Connect OpenAEV" when OpenAEV is not connected (disabled, with a read-only hint, for a user who
 * cannot configure the platform). Never an unframed icon. Silent while loading. Below 1280 px the
 * same states render as the framed icon button of the toolbar (OPENAEV_PIVOT_COMPACT_QUERY).
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
                href={OPENAEV_CONNECT_DOC_URL}
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
              href={OPENAEV_CONNECT_DOC_URL}
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
