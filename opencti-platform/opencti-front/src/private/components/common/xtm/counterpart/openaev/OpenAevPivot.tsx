import React from 'react';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import { useFormatter } from '../../../../../../components/i18n';
import { OaevLogo } from '../../../../../../static/images/logo_oaev';
import useGranted, { SETTINGS_SETPARAMETERS } from '../../../../../../utils/hooks/useGranted';
import useXtmCounterpart from '../core/useXtmCounterparts';
import { useCompactPivot } from '../core/useCompactPivot';
import { XTM_CONNECT_DOC_URL } from '../core/xtmConnect';
import { withTooltip } from '../core/XtmTooltip';
import { XtmPivotPreview, XtmPivotTeaser } from '../core/XtmPivotPreview';
import { factLabelsOf, OPENAEV_FACTS, previewFactsOf } from '../core/counterpartFacts';

interface OpenAevPivotProps {
  // The OpenCTI object: the server reads its key (hostname, MITRE id, CVE id or STIX id) under the caller's rights.
  objectId: string | null | undefined;
}

/**
 * Hero action of an object OpenAEV can also hold, rendered as the framed outlined text button of
 * the header toolbar: "Open in OpenAEV" on a match, with a preview on hover and focus (the object in
 * OpenAEV, its simulations, findings and affected assets, and what the click opens); a disabled
 * muted "OpenAEV is unavailable" when OpenAEV could not answer this time; and "Connect OpenAEV" when
 * OpenAEV is not connected, with a teaser of what it would show (disabled, with a read-only hint,
 * for a user who cannot configure the platform). Nothing at all when OpenAEV is connected and does
 * not hold the object, while loading, and when there is nothing to match (no key, an object the
 * caller cannot read, or an OpenAEV without this lookup). Below 1280 px the same states render as
 * the framed icon button of the toolbar (XTM_PIVOT_COMPACT_QUERY).
 */
const OpenAevPivot: React.FC<OpenAevPivotProps> = ({ objectId }) => {
  const { t_i18n, n, fd } = useFormatter();
  const canConfigure = useGranted([SETTINGS_SETPARAMETERS]);
  const state = useXtmCounterpart('openaev', objectId);
  const compact = useCompactPivot();

  let label: string;
  let tooltip: React.ReactNode;
  let href: string | undefined;
  let disabled = false;
  let ariaLabel: string | undefined;
  switch (state.status) {
    case 'match': {
      label = t_i18n('Open in OpenAEV');
      const { counterpart } = state;
      tooltip = (
        <XtmPivotPreview
          mark={<OaevLogo />}
          productName="OpenAEV"
          entityType={counterpart.object_type}
          name={counterpart.object_name}
          facts={previewFactsOf(counterpart.facts, OPENAEV_FACTS, { t_i18n, count: (v) => n(v), money: (v) => n(v), date: (v) => fd(v) })}
          action={t_i18n('See the simulations, findings and exposed assets of this object in OpenAEV.')}
        />
      );
      href = counterpart.object_url;
      break;
    }
    case 'unavailable':
      label = t_i18n('OpenAEV is unavailable');
      tooltip = label;
      disabled = true;
      break;
    case 'not_connected':
      label = t_i18n('Connect OpenAEV');
      tooltip = (
        <XtmPivotTeaser
          mark={<OaevLogo />}
          productName="OpenAEV"
          labels={factLabelsOf(OPENAEV_FACTS, t_i18n)}
          pitch={t_i18n('Connect OpenAEV to see how this object is simulated and what it exposes.')}
          next={canConfigure ? t_i18n('Open the documentation to connect it.') : t_i18n('Ask an administrator to connect it.')}
        />
      );
      if (canConfigure) {
        href = XTM_CONNECT_DOC_URL;
      } else {
        ariaLabel = t_i18n('OpenAEV is not connected');
        disabled = true;
      }
      break;
    default:
      // Loading, nothing to match, and connected without a match: nothing is drawn.
      return null;
  }
  const link = href ? { href, target: '_blank', rel: 'noopener noreferrer' } : {};

  if (compact) {
    return withTooltip(
      tooltip,
      <IconButton
        variant="secondary"
        size="default"
        disabled={disabled}
        aria-label={ariaLabel ?? label}
        data-testid="openaev-pivot"
        data-status={state.status}
        {...link}
      >
        <OaevLogo />
      </IconButton>,
    );
  }
  return withTooltip(
    tooltip,
    <Button
      variant="secondary"
      startIcon={<OaevLogo />}
      disabled={disabled}
      aria-label={ariaLabel}
      data-testid="openaev-pivot"
      data-status={state.status}
      {...link}
    >
      {label}
    </Button>,
  );
};

export default OpenAevPivot;
