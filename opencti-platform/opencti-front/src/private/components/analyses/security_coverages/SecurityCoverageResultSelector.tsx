import React, { FunctionComponent } from 'react';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { useFormatter } from '../../../../components/i18n';
import { ALL_RESULTS_VALUE, ResultOption, toResultId } from './securityCoverageResultScope';

interface SecurityCoverageResultSelectorProps {
  options: ResultOption[];
  // null = All results
  value: string | null;
  onChange: (securityCoverageResultId: string | null) => void;
}

const SecurityCoverageResultSelector: FunctionComponent<SecurityCoverageResultSelectorProps> = ({
  options,
  value,
  onChange,
}) => {
  const { t_i18n } = useFormatter();
  return (
    <Select
      value={value ?? ALL_RESULTS_VALUE}
      onValueChange={(selected) => onChange(toResultId(selected))}
    >
      <Tooltip>
        <TooltipTrigger asChild>
          <SelectTrigger aria-label={t_i18n('Security Coverage Result')}>
            {/* Radix: children replace the text of the selected item, undefined falls back to the item label */}
            <SelectValue>
              {value === null ? t_i18n('Security Coverage Result') : undefined}
            </SelectValue>
          </SelectTrigger>
        </TooltipTrigger>
        <TooltipContent>
          {t_i18n('Select Security Coverage Result to display results by instance')}
        </TooltipContent>
      </Tooltip>
      <SelectContent aria-label={t_i18n('Security Coverage Result')}>
        <SelectItem value={ALL_RESULTS_VALUE}>{t_i18n('All results')}</SelectItem>
        {options.map((option) => (
          <SelectItem key={option.value} value={option.value}>
            {option.label}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
};

export default SecurityCoverageResultSelector;
