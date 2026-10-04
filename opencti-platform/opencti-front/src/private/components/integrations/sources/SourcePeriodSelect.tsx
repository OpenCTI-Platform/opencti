import React from 'react';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@filigran/design-system';
import { useFormatter } from '../../../../components/i18n';
import { SCORECARD_PERIOD_LABELS, SCORECARD_PERIODS, ScorecardPeriod } from './sourceIntelligenceUtils';

interface SourcePeriodSelectProps {
  value: ScorecardPeriod;
  onChange: (period: ScorecardPeriod) => void;
}

const SourcePeriodSelect = ({ value, onChange }: SourcePeriodSelectProps) => {
  const { t_i18n } = useFormatter();
  return (
    <Select value={value} onValueChange={(next) => onChange(next as ScorecardPeriod)}>
      <SelectTrigger aria-label={t_i18n('Scorecard period')} data-testid="source-period-select">
        <SelectValue />
      </SelectTrigger>
      <SelectContent aria-label={t_i18n('Scorecard period')}>
        {SCORECARD_PERIODS.map((period) => (
          <SelectItem key={period} value={period}>{t_i18n(SCORECARD_PERIOD_LABELS[period])}</SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
};

export default SourcePeriodSelect;
