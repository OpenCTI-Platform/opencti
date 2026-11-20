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

interface OpenAevPivotProps {
  // The OpenCTI object: the server reads its key (hostname, MITRE id, CVE id or STIX id) under the caller's rights.
  objectId: string | null | undefined;
}

/**
 * Hero action of an object OpenAEV can also hold, rendered as the framed outlined text button of
 * the header toolbar (the same control as "Create Relationship", and the same language as OpenAEV's
 * "Open in OpenCTI"): "Open in OpenAEV" on a match, a disabled "Not in OpenAEV" without one, a
 * disabled muted "OpenAEV is unavailable" when OpenAEV could not answer this time, and "Connect
 * OpenAEV" when OpenAEV is not connected (disabled, with a read-only hint, for a user who cannot
 * configure the platform). Silent while loading, and when there is nothing to match (no key, an
 * object the caller cannot read, or an OpenAEV without this lookup). Below 1280 px the same states
 * render as the framed icon button of the toolbar (XTM_PIVOT_COMPACT_QUERY).
 */
const OpenAevPivot: React.FC<OpenAevPivotProps> = ({ objectId }) => {
  const { t_i18n } = useFormatter();
  const canConfigure = useGranted([SETTINGS_SETPARAMETERS]);
  const state = useXtmCounterpart('openaev', objectId);
  const compact = useCompactPivot();

  let label: string;
  let tooltip: string;
  let href: string | undefined;
  let disabled = false;
  let ariaLabel: string | undefined;
  switch (state.status) {
    case 'match':
      label = t_i18n('Open in OpenAEV');
      tooltip = state.counterpart.object_name ? `${label}: ${state.counterpart.object_name}` : label;
      href = state.counterpart.object_url;
      break;
    case 'no_match':
      label = t_i18n('Not in OpenAEV');
      tooltip = label;
      disabled = true;
      break;
    case 'unavailable':
      label = t_i18n('OpenAEV is unavailable');
      tooltip = label;
      disabled = true;
      break;
    case 'not_connected':
      label = t_i18n('Connect OpenAEV');
      if (canConfigure) {
        tooltip = t_i18n('Connect OpenAEV to pivot to this object and test it');
        href = XTM_CONNECT_DOC_URL;
      } else {
        tooltip = t_i18n('OpenAEV is not connected: ask an administrator to connect it');
        ariaLabel = t_i18n('OpenAEV is not connected');
        disabled = true;
      }
      break;
    default:
      return null;
  }
  const link = href ? { href, target: '_blank', rel: 'noopener noreferrer' } : {};

  if (compact) {
    return (
      <IconButton
        variant="secondary"
        size="default"
        disabled={disabled}
        aria-label={ariaLabel ?? label}
        tooltip={tooltip}
        data-testid="openaev-pivot"
        data-status={state.status}
        {...link}
      >
        <OaevLogo />
      </IconButton>
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
