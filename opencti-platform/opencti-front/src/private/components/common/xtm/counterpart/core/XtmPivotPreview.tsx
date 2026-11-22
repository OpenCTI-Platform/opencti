import React from 'react';
import Box from '@mui/material/Box';
import { Chip, Skeleton } from '@filigran/design-system';
import { useFormatter } from '../../../../../../components/i18n';

// The preview every cross-platform pivot of OpenCTI opens on hover and on keyboard focus: what the
// click brings. The design system has no hover card yet, so it is the content of the FDS Tooltip,
// laid out as a card: the product mark and the object's type, its name, the key facts the other
// product answered (under the caller's rights: a user without rights there sees none), and one line
// saying what can be done there. Same contract as OpenAEV's and OpenCRQ's XtmPivotPreview.

export type PreviewFact = { label: string; value: string };

interface PreviewProps {
  mark: React.ReactNode;
  productName: string;
  // The object's type in the other product (Vulnerability, Asset, Attack pattern...).
  entityType?: string | null;
  name?: string | null;
  facts: PreviewFact[];
  // What the user can do there, one line ("See the financial impact of this object...").
  action: string;
}

const FactList: React.FC<{ facts: PreviewFact[]; testId: string; example?: boolean }> = ({ facts, testId, example = false }) => (
  <Box
    component="dl"
    aria-hidden={example || undefined}
    data-testid={testId}
    sx={{ display: 'grid', gridTemplateColumns: 'max-content 1fr', columnGap: 2, rowGap: 0.5, m: 0, alignItems: 'center' }}
  >
    {facts.map((fact) => (
      <Box key={fact.label} sx={{ display: 'contents' }}>
        <Box component="dt" sx={{ opacity: 0.72 }}>{fact.label}</Box>
        <Box component="dd" sx={{ m: 0, fontWeight: example ? undefined : 600 }}>
          {example ? <Skeleton style={{ width: 56, height: 12 }} /> : fact.value}
        </Box>
      </Box>
    ))}
  </Box>
);

const Header: React.FC<{ mark: React.ReactNode; productName: string; chip?: string | null }> = ({ mark, productName, chip }) => (
  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, '& svg': { width: 16, height: 16 } }}>
    {mark}
    <Box component="span" sx={{ fontWeight: 600 }}>{productName}</Box>
    {chip && <Chip label={chip} />}
  </Box>
);

/** Match: the counterpart, its facts and what the click opens. */
export const XtmPivotPreview: React.FC<PreviewProps> = ({ mark, productName, entityType, name, facts, action }) => (
  <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1, minWidth: 220 }} data-testid="xtm-preview">
    <Header mark={mark} productName={productName} chip={entityType} />
    {name && <Box component="span" sx={{ fontWeight: 600 }}>{name}</Box>}
    {facts.length > 0 && <FactList facts={facts} testId="xtm-preview-facts" />}
    <Box component="span" sx={{ opacity: 0.72 }}>{action}</Box>
  </Box>
);

interface TeaserProps {
  mark: React.ReactNode;
  productName: string;
  // The fact labels the connected product would answer, shown with skeleton values labelled as an example.
  labels: string[];
  // Why connecting is worth it.
  pitch: string;
  // The next step for this user: the settings for a configurer, ask an administrator otherwise.
  next: string;
}

/**
 * Not connected: what the other product would show here, with skeleton values labelled as an
 * example (never figures that could read as real), the pitch and the next step.
 */
export const XtmPivotTeaser: React.FC<TeaserProps> = ({ mark, productName, labels, pitch, next }) => {
  const { t_i18n } = useFormatter();
  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1, minWidth: 220 }} data-testid="xtm-teaser">
      <Header mark={mark} productName={productName} chip={t_i18n('Example')} />
      <FactList facts={labels.map((label) => ({ label, value: '' }))} testId="xtm-teaser-facts" example />
      <Box component="span">{pitch}</Box>
      <Box component="span" sx={{ opacity: 0.72 }}>{next}</Box>
    </Box>
  );
};
