import React from 'react';
import { Chip } from '@filigran/design-system';
import Box from '@mui/material/Box';

// Shared rendering helpers of the output screens (Overview, Entities, Inbox) of the proof of concept.

export interface IrCriterionRef {
  readonly id: string;
  readonly name: string;
  readonly kind: string;
}

export interface IrExplanationData {
  readonly criterion_id: string;
  readonly kind: string;
  readonly relationship_type?: string | null;
  readonly direction?: string | null;
  readonly keyword?: string | null;
  readonly field?: string | null;
  readonly anchor?: { readonly representative: { readonly main: string } } | null;
  readonly container?: { readonly representative: { readonly main: string } } | null;
}

export const criterionName = (criteria: readonly IrCriterionRef[], id: string) => criteria.find((c) => c.id === id)?.name ?? id;

/**
 * One line of proof: why the entity entered the requirement.
 */
export const explanationText = (e: IrExplanationData) => {
  if (e.kind === 'graph') {
    const anchor = e.anchor?.representative.main ?? '?';
    return e.direction === 'incoming' ? `—${e.relationship_type}→ ${anchor}` : `${anchor} —${e.relationship_type}→`;
  }
  if (e.kind === 'keywords') {
    return `“${e.keyword}” in ${e.field} of ${e.container?.representative.main ?? 'itself'}`;
  }
  return 'matches the attribute filters';
};

export const STATUS_CHIP: Record<string, { label: string; severity: 'neutral' | 'info' | 'low' | 'medium' | 'high' | 'critical' }> = {
  auto: { label: 'Auto', severity: 'neutral' },
  accepted: { label: 'Accepted', severity: 'low' },
  proposed: { label: 'Proposed', severity: 'info' },
  rejected: { label: 'Rejected', severity: 'neutral' },
  removed: { label: 'Removed', severity: 'neutral' },
};

export const KIND_CHIP: Record<string, { label: string; severity: 'neutral' | 'info' | 'low' | 'medium' | 'high' | 'critical' }> = {
  proposed: { label: 'Proposed · to accept', severity: 'info' },
  entered: { label: 'Entered · for information', severity: 'neutral' },
  score: { label: 'Score threshold', severity: 'high' },
  health: { label: 'Requirement health', severity: 'medium' },
};

export const StatusChip = ({ status, excluded, t }: { status: string; excluded?: boolean; t: (s: string) => string }) => {
  if (excluded) return <Chip label={t('Excluded')} severity="critical" size="sm" />;
  const chip = STATUS_CHIP[status] ?? STATUS_CHIP.auto;
  return <Chip label={t(chip.label)} severity={chip.severity} size="sm" />;
};

export const ScoreBar = ({ score, excluded }: { score: number; excluded?: boolean }) => (
  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
    <Box sx={{ width: 70, height: 6, borderRadius: 3, bgcolor: 'action.hover', overflow: 'hidden' }}>
      <Box sx={{ width: `${excluded ? 0 : score}%`, height: '100%', background: 'linear-gradient(90deg, #42caff, #00f0bc)' }} />
    </Box>
    <Box component="span" sx={{ fontWeight: 600, fontSize: 13, minWidth: 26 }}>{excluded ? '—' : score}</Box>
  </Box>
);

export const IN_STATUSES = ['auto', 'accepted'];
