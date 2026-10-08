import React from 'react';
import { Chip } from '@filigran/design-system';
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
