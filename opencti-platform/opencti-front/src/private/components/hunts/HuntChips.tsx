import React from 'react';
import { Link } from 'react-router';
import { Chip, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { useFormatter } from '../../../components/i18n';
import {
  huntRunStatusLabel,
  huntRunStatusSeverity,
  huntSourceKindLabel,
  huntStatusLabel,
  huntStatusSeverity,
  huntTechniqueValidationLabel,
  huntTechniqueValidationSeverity,
  type HuntTechniqueValidationStatus,
  huntVerdictLabel,
  huntVerdictSeverity,
} from './hunt-utils';

interface RelativeDateProps {
  /** One date, or the dates of a sentence that names several */
  date: string | string[];
  label?: (...relative: string[]) => string;
  /** Where the text leads: the link itself carries the tooltip */
  to?: string;
  testId?: string;
}

/**
 * A date shown relative to now, the absolute date in its tooltip. A sentence naming several dates shows them all
 * relative, and the same sentence with the absolute dates in its tooltip.
 */
export const RelativeDate = ({ date, label, to, testId }: RelativeDateProps) => {
  const { fldt, rd } = useFormatter();
  const dates = Array.isArray(date) ? date : [date];
  const text = label ? label(...dates.map((value) => rd(value))) : rd(dates[0]);
  const absolute = label && dates.length > 1 ? label(...dates.map((value) => fldt(value))) : fldt(dates[0]);
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        {to ? (
          <Link to={to} data-testid={testId}>{text}</Link>
        ) : (
          // eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex
          <span tabIndex={0} data-testid={testId}>{text}</span>
        )}
      </TooltipTrigger>
      <TooltipContent>{absolute}</TooltipContent>
    </Tooltip>
  );
};

interface ValueChipProps {
  value?: string | null;
}

export const HuntStatusChip = ({ value }: ValueChipProps) => {
  const { t_i18n } = useFormatter();
  return <Chip label={t_i18n(huntStatusLabel(value))} severity={huntStatusSeverity(value)} data-testid="hunt-status-chip" />;
};

export const HuntRunStatusChip = ({ value }: ValueChipProps) => {
  const { t_i18n } = useFormatter();
  return <Chip label={t_i18n(huntRunStatusLabel(value))} severity={huntRunStatusSeverity(value)} data-testid="hunt-run-status-chip" />;
};

export const HuntVerdictChip = ({ value }: ValueChipProps) => {
  const { t_i18n } = useFormatter();
  return <Chip label={t_i18n(huntVerdictLabel(value))} severity={huntVerdictSeverity(value)} data-testid="hunt-verdict-chip" />;
};

export const HuntSourceKindChip = ({ value }: ValueChipProps) => {
  const { t_i18n } = useFormatter();
  return <Chip label={t_i18n(huntSourceKindLabel(value))} severity={value === 'analyst' ? 'neutral' : 'info'} />;
};

export const HuntTechniqueValidationChip = ({ status }: { status: HuntTechniqueValidationStatus }) => {
  const { t_i18n } = useFormatter();
  return <Chip label={t_i18n(huntTechniqueValidationLabel(status))} severity={huntTechniqueValidationSeverity(status)} />;
};
