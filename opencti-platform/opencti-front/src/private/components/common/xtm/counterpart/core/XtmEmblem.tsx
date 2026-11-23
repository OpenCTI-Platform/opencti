import React from 'react';
import Box from '@mui/material/Box';
import { Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import IconButton from '@common/button/IconButton';
import { useFormatter } from '../../../../../../components/i18n';
import useGranted, { SETTINGS_SETPARAMETERS } from '../../../../../../utils/hooks/useGranted';
import useXtmCounterpart, { type XtmCounterpart } from './useXtmCounterparts';
import { XTM_CONNECT_DOC_URL } from './xtmConnect';
import { XtmMark } from './XtmMark';
import { XtmPivotPreview, XtmPivotTeaser } from './XtmPivotPreview';
import { factLabelsOf, previewFactsOf } from './counterpartFacts';
import type { XtmProduct } from './xtmProducts';

// Contract v3 (Sam, 22 Nov 2026), identical in OpenCTI, OpenAEV and OpenCRQ: one icon-only emblem
// per counterpart product in the header, at the size of the sibling header actions, no text.
// - connected and found: the emblem in the theme primary, a link to the counterpart, the preview
//   of its facts on hover and keyboard focus;
// - connected and not found: the emblem greyed, still focusable, tooltip "Not found in X" and how
//   an object gets there;
// - not connected: the emblem greyed, the teaser (what X would show, example skeletons), a link to
//   the connection documentation for a user who can configure the platform, a read-only hint else;
// - unavailable (X could not answer this time): the emblem greyed, "X is unavailable".
// Nothing while loading and for an object X has no counterpart for.

// Two colours only, the same for every product and the same hex in OpenCTI, OpenAEV and OpenCRQ
// (Sam, 22 Nov 2026): found = the design system's highlight ink (--icon-highlight, the brand primary
// of the theme, a custom primary included), not found, not connected and unavailable = its disabled
// ink (--icon-disabled). Design system tokens, never the MUI palette, so the three products agree.
// The one exception is XTM One, whose found emblem keeps the XTM One purple (product.foundColor).
export const EMBLEM_FOUND = 'var(--icon-highlight)';
export const EMBLEM_MUTED = 'var(--icon-disabled)';

/** The ink of a product's emblem: its found ink when active, the disabled ink otherwise. */
export const emblemInk = (product: XtmProduct, active: boolean): string => (active ? (product.foundColor ?? EMBLEM_FOUND) : EMBLEM_MUTED);

interface XtmEmblemProps {
  product: XtmProduct;
  // The OpenCTI object: the server reads its key under the caller's rights.
  objectId: string | null | undefined;
}

/** The preview of a match: shared by the header emblem and the list-row mark. */
export const XtmCounterpartPreview: React.FC<{ product: XtmProduct; counterpart: XtmCounterpart }> = ({ product, counterpart }) => {
  const { t_i18n, n, fd } = useFormatter();
  return (
    <XtmPivotPreview
      mark={<XtmMark src={product.mark} size={16} color={emblemInk(product, true)} />}
      productName={product.name}
      entityType={counterpart.object_type}
      name={counterpart.object_name}
      facts={previewFactsOf(counterpart.facts, product.facts, { t_i18n, count: (v) => n(v), money: (v) => n(v), date: (v) => fd(v) })}
      action={t_i18n(product.action)}
    />
  );
};

const NotFound: React.FC<{ product: XtmProduct }> = ({ product }) => {
  const { t_i18n } = useFormatter();
  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5, maxWidth: 288 }} data-testid="xtm-not-found">
      <Box component="span" sx={{ fontWeight: 600 }}>{t_i18n(product.notFound)}</Box>
      <Box component="span" sx={{ opacity: 0.72 }}>{t_i18n(product.howItGetsThere)}</Box>
    </Box>
  );
};

export const XtmEmblem: React.FC<XtmEmblemProps> = ({ product, objectId }) => {
  const { t_i18n } = useFormatter();
  const canConfigure = useGranted([SETTINGS_SETPARAMETERS]);
  const state = useXtmCounterpart(product.product, objectId);

  let label: string;
  let tooltip: React.ReactNode;
  let href: string | undefined;
  let active = false;
  switch (state.status) {
    case 'match':
      label = t_i18n(product.open);
      tooltip = <XtmCounterpartPreview product={product} counterpart={state.counterpart} />;
      href = state.counterpart.object_url;
      active = true;
      break;
    case 'no_match':
      label = t_i18n(product.notFound);
      tooltip = <NotFound product={product} />;
      break;
    case 'unavailable':
      label = t_i18n(product.unavailable);
      tooltip = label;
      break;
    case 'not_connected':
      label = canConfigure ? t_i18n(product.connect) : t_i18n(product.notConnected);
      tooltip = (
        <XtmPivotTeaser
          mark={<XtmMark src={product.mark} size={16} color={EMBLEM_MUTED} />}
          productName={product.name}
          labels={factLabelsOf(product.facts, t_i18n)}
          pitch={t_i18n(product.pitch)}
          next={canConfigure ? t_i18n('Open the documentation to connect it.') : t_i18n('Ask an administrator to connect it.')}
        />
      );
      if (canConfigure) href = XTM_CONNECT_DOC_URL;
      break;
    default:
      return null;
  }
  const link = href ? { href, target: '_blank', rel: 'noopener noreferrer' } : {};
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <IconButton
          variant="secondary"
          size="default"
          aria-label={label}
          // Greyed but still focusable, so keyboard focus opens the tooltip too.
          aria-disabled={!active && !href ? true : undefined}
          data-testid={`${product.product}-emblem`}
          data-status={state.status}
          {...link}
        >
          <XtmMark src={product.mark} color={emblemInk(product, active)} />
        </IconButton>
      </TooltipTrigger>
      <TooltipContent>{tooltip}</TooltipContent>
    </Tooltip>
  );
};

/**
 * The emblems of the products an object can have a counterpart in, in the order of Contract v3
 * (XTM One leftmost, then OpenAEV, then OpenCRQ: OpenCTI is self).
 */
export const XtmEmblems: React.FC<{ products: ReadonlyArray<XtmProduct>; objectId: string | null | undefined }> = ({ products, objectId }) => (
  <>
    {products.map((product) => <XtmEmblem key={product.product} product={product} objectId={objectId} />)}
  </>
);

/**
 * List-row mark: the 16 px emblem in the theme primary, only when the product holds the object;
 * nothing on the row otherwise (the header carries the other states). The lookups of every row of
 * a page go out batched in one query.
 */
export const XtmRowMark: React.FC<XtmEmblemProps> = ({ product, objectId }) => {
  const { t_i18n } = useFormatter();
  const state = useXtmCounterpart(product.product, objectId);
  if (state.status !== 'match') return null;
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Box
          component="a"
          href={state.counterpart.object_url}
          target="_blank"
          rel="noopener noreferrer"
          aria-label={t_i18n(product.open)}
          data-testid={`${product.product}-row-mark`}
          // The row is itself a link: the mark opens the product without opening the row.
          onClick={(event: React.MouseEvent) => event.stopPropagation()}
          sx={{ display: 'inline-flex', alignItems: 'center', flexShrink: 0, ml: 0.5, verticalAlign: 'middle' }}
        >
          <XtmMark src={product.mark} size={16} color={emblemInk(product, true)} />
        </Box>
      </TooltipTrigger>
      <TooltipContent><XtmCounterpartPreview product={product} counterpart={state.counterpart} /></TooltipContent>
    </Tooltip>
  );
};
