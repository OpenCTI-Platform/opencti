import React from 'react';
import { useIntl } from 'react-intl';
import { Box } from '@mui/material';
import { Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { useFormatter } from '../../../../components/i18n';
import type { ScorecardMetricType } from './sourceIntelligenceUtils';

const isNumber = (value: number | null | undefined): value is number => typeof value === 'number' && Number.isFinite(value);

/**
 * Locale-aware formatting of scorecard values. Returns null when the value was not measured, so that callers show
 * "Not measured" instead of a placeholder.
 */
export const useSourceMetricFormat = () => {
  const intl = useIntl();
  const ratio = (value: number | null | undefined, digits = 1) => {
    return isNumber(value) ? intl.formatNumber(value, { style: 'percent', maximumFractionDigits: digits }) : null;
  };
  const score = (value: number | null | undefined) => (isNumber(value) ? intl.formatNumber(Math.round(value)) : null);
  const count = (value: number | null | undefined) => {
    return isNumber(value) ? intl.formatNumber(value, { notation: Math.abs(value) >= 10000 ? 'compact' : 'standard', maximumFractionDigits: 1 }) : null;
  };
  // Durations below two days stay in hours, longer ones in days; the sign carries the lead / lag meaning
  const hours = (value: number | null | undefined) => {
    if (!isNumber(value)) return null;
    const inDays = Math.abs(value) >= 48;
    return intl.formatNumber(inDays ? value / 24 : value, { style: 'unit', unit: inDays ? 'day' : 'hour', unitDisplay: 'narrow', maximumFractionDigits: 1 });
  };
  const cost = (value: number | null | undefined, currency?: string | null) => {
    if (!isNumber(value)) return null;
    const digits = value >= 100 ? 0 : 2;
    if (currency) {
      try {
        return intl.formatNumber(value, { style: 'currency', currency, maximumFractionDigits: value >= 1 ? digits : 4 });
      } catch {
        // A currency code unknown to the browser keeps the plain amount followed by the code
      }
    }
    const amount = intl.formatNumber(value, { maximumFractionDigits: value >= 1 ? digits : 4 });
    return currency ? `${amount} ${currency}` : amount;
  };
  const metric = (value: number | null | undefined, type: ScorecardMetricType, currency?: string | null) => {
    switch (type) {
      case 'ratio':
        return ratio(value);
      case 'hours':
        return hours(value);
      case 'cost':
        return cost(value, currency);
      case 'score':
        return score(value);
      default:
        return count(value);
    }
  };
  return { ratio, score, count, hours, cost, metric };
};

interface SourceMetricValueProps {
  value: string | null;
  // Why the value is missing, shown on hover
  reason?: string;
}

/**
 * A formatted scorecard value, or a muted "Not measured" with its reason: a missing measure never looks like a value.
 */
const SourceMetricValue = ({ value, reason }: SourceMetricValueProps) => {
  const { t_i18n } = useFormatter();
  if (value !== null) {
    return <>{value}</>;
  }
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Box component="span" tabIndex={0} sx={{ color: 'text.disabled' }}>{t_i18n('Not measured')}</Box>
      </TooltipTrigger>
      <TooltipContent>
        <Box component="span" sx={{ display: 'block', fontWeight: 'fontWeightMedium' }}>{t_i18n('Not measured')}</Box>
        <Box component="span" sx={{ display: 'block' }}>{reason ?? t_i18n('No sample for this measure in the period.')}</Box>
      </TooltipContent>
    </Tooltip>
  );
};

/**
 * A date as relative time ("3 hours ago"), with the absolute date and time on hover.
 */
export const RelativeTime = ({ date }: { date: string }) => {
  const { rd, fldt } = useFormatter();
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Box component="time" dateTime={date} tabIndex={0} sx={{ whiteSpace: 'nowrap' }}>{rd(date)}</Box>
      </TooltipTrigger>
      <TooltipContent>{fldt(date)}</TooltipContent>
    </Tooltip>
  );
};

export default SourceMetricValue;
