import React, { useState } from 'react';
import Box from '@mui/material/Box';
import Popover from '@mui/material/Popover';
import { Chip, Paper, Separator, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import { useFormatter } from '../../../../../../components/i18n';
import useGranted, { SETTINGS_SETPARAMETERS } from '../../../../../../utils/hooks/useGranted';
import useXtmCounterpart, { useXtmCounterpartStates, type XtmCounterpart, type XtmCounterpartState } from './useXtmCounterparts';
import { XTM_CONNECT_DOC_URL } from './xtmConnect';
import { XtmMark } from './XtmMark';
import { XtmPivotPreview } from './XtmPivotPreview';
import { previewFactsOf, type FactFormatters } from './counterpartFacts';
import { XTMONE_PRODUCT, type XtmProduct } from './xtmProducts';

// One emblem per object, identical in OpenCTI, OpenAEV and OpenCRQ (Sam, 23 Nov 2026): the XTM One
// mark of the product switcher, in one header slot. Purple when at least one other product holds the
// object, grey otherwise. A click opens a small anchored surface (a popover, never a dialog) with one
// section per product: its status, the facts it answered and a button to open the object there.
// - not connected: a "Connect X" entry for a user who can configure the platform, nothing else;
// - not supported (the product has no lookup for this object, or answers 404): the product is left out;
// - nothing at all to show (no product connected and the user cannot connect one): no emblem.
// Everything sits behind the dedicated feature flag XTM_COUNTERPARTS (off by default).

// Design system inks, the same in the three products.
export const EMBLEM_FOUND = 'var(--color-filigran-ia-primary)';
export const EMBLEM_MUTED = 'var(--icon-disabled)';
// The outline of the emblem button: the XTM One purple in every state, found or not, hover and focus
// included (Sam, 24 Nov 2026), the same token in OpenCTI, OpenAEV and OpenCRQ. The design system's
// hover fill and focus ring are kept.
export const EMBLEM_OUTLINE = 'var(--color-filigran-ia-primary)';
// Secondary ink of labels and explanations, a token the design system defines.
export const SECONDARY_INK = 'var(--text-default-secondary)';

/** The ink of a product mark: its found ink when active, the disabled ink otherwise. */
export const emblemInk = (product: XtmProduct, active: boolean): string => (active ? (product.foundColor ?? 'var(--icon-highlight)') : EMBLEM_MUTED);

/** A counterpart link is followed only when it is an http(s) address. */
export const safeCounterpartUrl = (url: string | null | undefined): string | undefined => {
  if (!url) return undefined;
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'https:' || parsed.protocol === 'http:' ? parsed.toString() : undefined;
  } catch {
    return undefined;
  }
};

const useFactFormatters = (): FactFormatters => {
  const { t_i18n, n, fd } = useFormatter();
  return { t_i18n, count: (v) => n(v), money: (v) => n(v), date: (v) => fd(v) };
};

/** The preview of a match, used by the list-row mark tooltip. */
export const XtmCounterpartPreview: React.FC<{ product: XtmProduct; counterpart: XtmCounterpart }> = ({ product, counterpart }) => {
  const { t_i18n } = useFormatter();
  const formatters = useFactFormatters();
  return (
    <XtmPivotPreview
      mark={<XtmMark src={product.mark} size={16} color={emblemInk(product, true)} />}
      productName={product.name}
      entityType={counterpart.object_type}
      name={counterpart.object_name}
      facts={previewFactsOf(counterpart.facts, product.facts, formatters)}
      action={t_i18n(product.action)}
    />
  );
};

type SectionKind = 'found' | 'not_found' | 'unavailable' | 'not_connected';

const sectionKindOf = (state: XtmCounterpartState): SectionKind | null => {
  switch (state.status) {
    case 'match':
      return 'found';
    case 'no_match':
      return 'not_found';
    case 'unavailable':
      return 'unavailable';
    case 'not_connected':
      return 'not_connected';
    default:
      return null;
  }
};

const ProductSection: React.FC<{ product: XtmProduct; state: XtmCounterpartState; kind: SectionKind }> = ({ product, state, kind }) => {
  const { t_i18n } = useFormatter();
  const formatters = useFactFormatters();
  const status: Record<SectionKind, { label: string; severity: 'info' | 'neutral' | 'medium' }> = {
    found: { label: t_i18n('Found'), severity: 'info' },
    not_found: { label: t_i18n('Not found'), severity: 'neutral' },
    unavailable: { label: t_i18n('Unavailable'), severity: 'medium' },
    not_connected: { label: t_i18n('Not connected'), severity: 'neutral' },
  };
  const counterpart = state.status === 'match' ? state.counterpart : null;
  const facts = counterpart ? previewFactsOf(counterpart.facts, product.facts, formatters) : [];
  const href = counterpart ? safeCounterpartUrl(counterpart.object_url) : undefined;
  return (
    <Box component="section" aria-label={product.name} data-testid={`${product.product}-section`} data-status={kind} sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
        <XtmMark src={product.mark} size={16} color={emblemInk(product, kind === 'found')} />
        <Box component="span" sx={{ fontWeight: 600, flex: 1 }}>{product.name}</Box>
        <Chip label={status[kind].label} severity={status[kind].severity} />
      </Box>
      {counterpart && (
        <>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, minWidth: 0 }}>
            {counterpart.object_type && <Chip label={counterpart.object_type} />}
            {counterpart.object_name && (
              <Box component="span" sx={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{counterpart.object_name}</Box>
            )}
          </Box>
          {facts.length > 0 && (
            <Box component="dl" sx={{ display: 'grid', gridTemplateColumns: 'max-content 1fr', columnGap: 2, rowGap: 0.5, m: 0 }}>
              {facts.map((fact) => (
                <Box key={fact.label} sx={{ display: 'contents' }}>
                  <Box component="dt" sx={{ color: SECONDARY_INK }}>{fact.label}</Box>
                  <Box component="dd" sx={{ m: 0, fontWeight: 600 }}>{fact.value}</Box>
                </Box>
              ))}
            </Box>
          )}
        </>
      )}
      {kind === 'not_found' && <Box component="span" sx={{ color: SECONDARY_INK }}>{t_i18n(product.howItGetsThere)}</Box>}
      {kind === 'unavailable' && <Box component="span" sx={{ color: SECONDARY_INK }}>{t_i18n(product.unavailable)}</Box>}
      {href && (
        <Box>
          <Button variant="secondary" size="small" href={href} target="_blank" rel="noopener noreferrer">{t_i18n(product.open)}</Button>
        </Box>
      )}
      {kind === 'not_connected' && (
        <Box>
          <Button variant="secondary" size="small" href={XTM_CONNECT_DOC_URL} target="_blank" rel="noopener noreferrer">{t_i18n(product.connect)}</Button>
        </Box>
      )}
    </Box>
  );
};

interface XtmEmblemProps {
  // The products that can hold this object, in display order (xtmProductsFor).
  products: ReadonlyArray<XtmProduct>;
  // The OpenCTI object: the server reads its key under the caller's rights.
  objectId: string | null | undefined;
}

/** The single XTM emblem of an object header, and its cross-product surface. */
export const XtmEmblem: React.FC<XtmEmblemProps> = ({ products, objectId }) => {
  const { t_i18n } = useFormatter();
  const canConfigure = useGranted([SETTINGS_SETPARAMETERS]);
  const states = useXtmCounterpartStates(products.map((p) => p.product), objectId);
  const [anchor, setAnchor] = useState<HTMLElement | null>(null);
  const open = Boolean(anchor);

  const sections = products
    .map((product) => ({ product, state: states[product.product] ?? { status: 'loading' as const } }))
    .map(({ product, state }) => ({ product, state, kind: sectionKindOf(state) }))
    // Not connected is shown to settings managers only; not supported is never listed.
    .filter((s): s is { product: XtmProduct; state: XtmCounterpartState; kind: SectionKind } => s.kind !== null && (s.kind !== 'not_connected' || canConfigure));
  if (sections.length === 0) return null;
  const found = sections.filter((s) => s.kind === 'found').length;
  const label = found > 0 ? t_i18n('Across the XTM Platform') : t_i18n('Not found across the XTM Platform');
  return (
    <>
      <Tooltip>
        <TooltipTrigger asChild>
          <IconButton
            variant="secondary"
            size="default"
            aria-label={label}
            aria-haspopup="dialog"
            aria-expanded={open}
            data-testid="xtm-emblem"
            data-found={found}
            style={{ borderColor: EMBLEM_OUTLINE }}
            onClick={(event: React.MouseEvent<HTMLElement>) => setAnchor(event.currentTarget)}
          >
            <XtmMark src={XTMONE_PRODUCT.mark} color={found > 0 ? EMBLEM_FOUND : EMBLEM_MUTED} />
          </IconButton>
        </TooltipTrigger>
        <TooltipContent>{label}</TooltipContent>
      </Tooltip>
      <Popover
        open={open}
        anchorEl={anchor}
        onClose={() => setAnchor(null)}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
        transformOrigin={{ vertical: 'top', horizontal: 'right' }}
        slotProps={{ paper: { sx: { background: 'transparent', boxShadow: 'none', mt: 1 } } }}
      >
        <Paper elevation={2} padding={16} data-testid="xtm-surface" role="dialog" aria-label={t_i18n('Across the XTM Platform')}>
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, width: 320 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <XtmMark src={XTMONE_PRODUCT.mark} size={16} color={found > 0 ? EMBLEM_FOUND : EMBLEM_MUTED} />
              <Box component="span" sx={{ fontWeight: 600 }}>{t_i18n('Across the XTM Platform')}</Box>
            </Box>
            {sections.map(({ product, state, kind }, index) => (
              <React.Fragment key={product.product}>
                {index > 0 && <Separator variant="subtle" data-testid="xtm-surface-separator" />}
                <ProductSection product={product} state={state} kind={kind} />
              </React.Fragment>
            ))}
          </Box>
        </Paper>
      </Popover>
    </>
  );
};

/**
 * List-row mark: the 16 px emblem of a product, only when it holds the object; nothing on the
 * row otherwise (the header carries the other states). Unchanged by the single emblem until the UX
 * round decides; behind the same feature flag (useXtmCounterpart answers 'none' while it is off).
 */
export const XtmRowMark: React.FC<{ product: XtmProduct; objectId: string | null | undefined }> = ({ product, objectId }) => {
  const { t_i18n } = useFormatter();
  const state = useXtmCounterpart(product.product, objectId);
  if (state.status !== 'match') return null;
  const href = safeCounterpartUrl(state.counterpart.object_url);
  if (!href) return null;
  // The row is itself a link (DataTableLine, SystemLine): the mark is a span with the link role, never
  // an <a> inside the row's <a>, and opens the product in a new tab without opening the row.
  const open = (event: React.SyntheticEvent) => {
    event.preventDefault();
    event.stopPropagation();
    window.open(href, '_blank', 'noopener,noreferrer');
  };
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Box
          component="span"
          role="link"
          tabIndex={0}
          aria-label={t_i18n(product.open)}
          data-testid={`${product.product}-row-mark`}
          onClick={open}
          onKeyDown={(event: React.KeyboardEvent) => {
            if (event.key === 'Enter') open(event);
          }}
          sx={{ display: 'inline-flex', alignItems: 'center', flexShrink: 0, ml: 0.5, verticalAlign: 'middle', cursor: 'pointer' }}
        >
          <XtmMark src={product.mark} size={16} color={emblemInk(product, true)} />
        </Box>
      </TooltipTrigger>
      <TooltipContent><XtmCounterpartPreview product={product} counterpart={state.counterpart} /></TooltipContent>
    </Tooltip>
  );
};
