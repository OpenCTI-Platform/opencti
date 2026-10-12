import React from 'react';
import { useTheme } from '@mui/styles';
import { SourceBranch } from 'mdi-material-ui';
import Tag from '../../../../components/common/tag/Tag';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import { corroborationColor, corroborationLevel } from './provenanceUtils';

interface ProvenanceBadgeProps {
  corroborationCount?: number | null;
  freshnessDays?: number | null;
  stale?: boolean | null;
  hasConflicts?: boolean | null;
}

/**
 * Number of distinct sources asserting the element, colored by corroboration level.
 */
const ProvenanceBadge = ({ corroborationCount, freshnessDays, stale, hasConflicts }: ProvenanceBadgeProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const level = corroborationLevel(corroborationCount);
  if (level === 'none') {
    return <span data-testid="provenance-badge-empty">-</span>;
  }
  const count = corroborationCount ?? 0;
  const label = t_i18n('{count, plural, one {# source} other {# sources}}', { values: { count } });
  const details = [
    level === 'single' ? t_i18n('Single sourced') : t_i18n('Corroborated'),
    freshnessDays !== null && freshnessDays !== undefined
      ? t_i18n('{days, plural, =0 {Last asserted today} one {Last asserted # day ago} other {Last asserted # days ago}}', { values: { days: freshnessDays } })
      : null,
    stale ? t_i18n('Stale knowledge') : null,
    hasConflicts ? t_i18n('Sources disagree on some fields') : null,
  ].filter((detail) => detail !== null).join(' - ');
  return (
    <span data-testid="provenance-badge" data-corroboration={count}>
      <Tag
        label={label}
        labelTextTransform="none"
        color={corroborationColor(theme, count)}
        icon={<SourceBranch fontSize="small" />}
        tooltipTitle={details}
        size="small"
      />
    </span>
  );
};

export default ProvenanceBadge;
