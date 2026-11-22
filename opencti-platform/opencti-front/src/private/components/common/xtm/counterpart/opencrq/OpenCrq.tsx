import React from 'react';
import Box from '@mui/material/Box';
import { Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import { useFormatter } from '../../../../../../components/i18n';
import { OcrqLogo } from '../../../../../../static/images/logo_ocrq';
import useGranted, { SETTINGS_SETPARAMETERS } from '../../../../../../utils/hooks/useGranted';
import { useCompactPivot } from '../core/useCompactPivot';
import { XTM_CONNECT_DOC_URL } from '../core/xtmConnect';
import { withTooltip } from '../core/XtmTooltip';
import { XtmPivotPreview, XtmPivotTeaser } from '../core/XtmPivotPreview';
import { factLabelsOf, OPENCRQ_FACTS, previewFactsOf } from '../core/counterpartFacts';
import useXtmCounterpart, { type XtmCounterpart } from '../core/useXtmCounterparts';

// The OpenCRQ side of the cross-platform pivots: same controls, states and wording as the OpenAEV
// ones (OpenAevPivot, OpenAevRowMark), the OpenCRQ mark, and the risk OpenCRQ quantifies for the
// object in the preview (annual loss expectancy, the risk scenarios it drives and, for a CVE, the
// loss avoided by fixing it). OpenCRQ holds threats (STIX id), vulnerabilities (CVE) and assets
// (hostname); attack patterns and alerts have no OpenCRQ counterpart.

export const OPENCRQ_PRODUCT = 'opencrq';

interface OpenCrqProps {
  // The OpenCTI object: the server reads its key (hostname, CVE id or STIX id) under the caller's
  // rights; a type OpenCRQ does not hold answers not_supported and nothing is drawn.
  objectId: string | null | undefined;
}

/** The preview of an OpenCRQ counterpart: the object, the risk it drives, and what the click opens. */
const OpenCrqPreview: React.FC<{ counterpart: XtmCounterpart }> = ({ counterpart }) => {
  const { t_i18n, n, fd } = useFormatter();
  return (
    <XtmPivotPreview
      mark={<OcrqLogo />}
      productName="OpenCRQ"
      entityType={counterpart.object_type}
      name={counterpart.object_name}
      facts={previewFactsOf(counterpart.facts, OPENCRQ_FACTS, { t_i18n, count: (v) => n(v), money: (v) => n(v), date: (v) => fd(v) })}
      action={t_i18n('See the financial impact of this object and the risk scenarios it drives in OpenCRQ.')}
    />
  );
};

/**
 * Hero action of an object OpenCRQ can also hold, beside "Open in OpenAEV": "Open in OpenCRQ" on a
 * match, with the risk preview on hover and focus; a disabled muted "OpenCRQ is unavailable" when
 * OpenCRQ could not answer this time; and "Connect OpenCRQ" when OpenCRQ is not connected, with a
 * teaser of what it would show (disabled, with a read-only hint, for a user who cannot configure the
 * platform). Nothing when OpenCRQ is connected and does not hold the object, while loading, and when
 * there is nothing to match. Below 1280 px the same states render as the framed icon button.
 */
export const OpenCrqPivot: React.FC<OpenCrqProps> = ({ objectId }) => {
  const { t_i18n } = useFormatter();
  const canConfigure = useGranted([SETTINGS_SETPARAMETERS]);
  const state = useXtmCounterpart(OPENCRQ_PRODUCT, objectId);
  const compact = useCompactPivot();

  let label: string;
  let tooltip: React.ReactNode;
  let href: string | undefined;
  let disabled = false;
  switch (state.status) {
    case 'match':
      label = t_i18n('Open in OpenCRQ');
      tooltip = <OpenCrqPreview counterpart={state.counterpart} />;
      href = state.counterpart.object_url;
      break;
    case 'unavailable':
      label = t_i18n('OpenCRQ is unavailable');
      tooltip = label;
      disabled = true;
      break;
    case 'not_connected':
      label = t_i18n('Connect OpenCRQ');
      tooltip = (
        <XtmPivotTeaser
          mark={<OcrqLogo />}
          productName="OpenCRQ"
          labels={factLabelsOf(OPENCRQ_FACTS, t_i18n)}
          pitch={t_i18n('Connect OpenCRQ to see the annual loss this object drives.')}
          next={canConfigure ? t_i18n('Open the documentation to connect it.') : t_i18n('Ask an administrator to connect it.')}
        />
      );
      if (canConfigure) {
        href = XTM_CONNECT_DOC_URL;
      } else {
        disabled = true;
      }
      break;
    default:
      // Loading, nothing to match, and connected without a match: nothing is drawn.
      return null;
  }
  const ariaLabel = state.status === 'not_connected' && disabled ? t_i18n('OpenCRQ is not connected') : label;
  const link = href ? { href, target: '_blank', rel: 'noopener noreferrer' } : {};

  if (compact) {
    return withTooltip(
      tooltip,
      <IconButton
        variant="secondary"
        size="default"
        disabled={disabled}
        aria-label={ariaLabel}
        data-testid="opencrq-pivot"
        data-status={state.status}
        {...link}
      >
        <OcrqLogo />
      </IconButton>,
    );
  }
  return withTooltip(
    tooltip,
    <Button
      variant="secondary"
      startIcon={<OcrqLogo />}
      disabled={disabled}
      aria-label={disabled ? ariaLabel : undefined}
      data-testid="opencrq-pivot"
      data-status={state.status}
      {...link}
    >
      {label}
    </Button>,
  );
};

/**
 * List-row mark of an object OpenCRQ also holds: a small OpenCRQ mark linking to the counterpart,
 * with the risk preview on hover and focus. Nothing while loading, without a match, when OpenCRQ is
 * unavailable or not connected (the hero carries the CTA). The lookups of every row go out in the
 * same batched query as the OpenAEV ones.
 */
export const OpenCrqRowMark: React.FC<OpenCrqProps> = ({ objectId }) => {
  const { t_i18n } = useFormatter();
  const state = useXtmCounterpart(OPENCRQ_PRODUCT, objectId);
  if (state.status !== 'match') return null;
  const { object_url } = state.counterpart;
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Box
          component="a"
          href={object_url}
          target="_blank"
          rel="noopener noreferrer"
          aria-label={t_i18n('Open in OpenCRQ')}
          // The row is itself a link: the mark opens OpenCRQ without opening the row.
          onClick={(event: React.MouseEvent) => event.stopPropagation()}
          data-testid="opencrq-row-mark"
          sx={{
            display: 'inline-flex',
            alignItems: 'center',
            flexShrink: 0,
            ml: 0.5,
            verticalAlign: 'middle',
            '& svg': { width: 16, height: 16 },
          }}
        >
          <OcrqLogo />
        </Box>
      </TooltipTrigger>
      <TooltipContent><OpenCrqPreview counterpart={state.counterpart} /></TooltipContent>
    </Tooltip>
  );
};
