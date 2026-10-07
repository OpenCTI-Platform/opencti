import React, { useEffect, useMemo } from 'react';
import { Select, SelectContent, SelectItem, SelectLabel, SelectTrigger, SelectValue, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { useFormatter } from '../../../components/i18n';
import useAuth from '../../../utils/hooks/useAuth';
import {
  BREAKDOWN_LIMIT_OPTIONS,
  getBreakdownEntityTypes,
  getBreakdownFieldOptions,
  getWidgetBreakdownLimit,
  isBreakdownField,
  isWidgetBreakdownEligible,
} from '../../../utils/widget/widgetBreakdown';
import { useWidgetConfigContext } from './WidgetConfigContext';

/**
 * Breakdown choice, made next to the datasets: the fields it offers depend on the dataset filters,
 * and a breakdown excludes adding other datasets.
 */
const WidgetBreakdownSelection = () => {
  const { t_i18n } = useFormatter();
  const { schema: { filterKeysSchema } } = useAuth();
  const { config, setConfigWidget, host } = useWidgetConfigContext();
  const { dataSelection, parameters } = config.widget;

  // The widget could be broken down, once reduced to its first dataset
  const isSupported = isWidgetBreakdownEligible({ ...config.widget, dataSelection: dataSelection.slice(0, 1) }, host);
  const isSingleDataset = dataSelection.length === 1;
  const fieldOptions = useMemo(
    () => (isSupported && isSingleDataset ? getBreakdownFieldOptions(filterKeysSchema, getBreakdownEntityTypes(dataSelection[0].filters)) : []),
    [isSupported, isSingleDataset, filterKeysSchema, dataSelection],
  );
  const breakdownBy = isBreakdownField(parameters.breakdownBy) ? parameters.breakdownBy : null;
  const isFieldAvailable = fieldOptions.some(({ key }) => key === breakdownBy);

  const setParameters = (changes: Partial<typeof parameters>) => {
    setConfigWidget({ ...config.widget, parameters: { ...config.widget.parameters, ...changes } });
  };

  // Filters changed to types without this field: drop the breakdown rather than keeping a field the API refuses
  useEffect(() => {
    if (isSingleDataset && breakdownBy && !isFieldAvailable) {
      setParameters({ breakdownBy: null });
    }
  }, [isSingleDataset, breakdownBy, isFieldAvailable]);

  if (!isSupported) {
    return null;
  }

  const fieldSelect = (
    <Select
      value={isFieldAvailable && breakdownBy ? breakdownBy : 'none'}
      onValueChange={(value: string) => setParameters({ breakdownBy: value === 'none' ? null : value })}
      disabled={!isSingleDataset}
    >
      <SelectLabel>{t_i18n('Break down by')}</SelectLabel>
      <SelectTrigger className="w-full">
        <SelectValue />
      </SelectTrigger>
      <SelectContent aria-label={t_i18n('Break down by')}>
        <SelectItem value="none">{t_i18n('None')}</SelectItem>
        {fieldOptions.map(({ key, label }) => (
          <SelectItem key={key} value={key}>
            {t_i18n(label)}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );

  return (
    <div style={{ display: 'flex', gap: 20, marginBottom: 20 }} data-testid="widget-breakdown-selection">
      <div style={{ flex: 2 }}>
        {isSingleDataset ? fieldSelect : (
          <Tooltip>
            <TooltipTrigger asChild>
              {/* A disabled field gets no pointer events: the wrapper carries the tooltip */}
              <div tabIndex={0}>{fieldSelect}</div>
            </TooltipTrigger>
            <TooltipContent>{t_i18n('A breakdown uses a single dataset.')}</TooltipContent>
          </Tooltip>
        )}
      </div>
      {isSingleDataset && isFieldAvailable && (
        <div style={{ flex: 1 }}>
          <Select
            value={String(getWidgetBreakdownLimit(parameters))}
            onValueChange={(value: string) => setParameters({ breakdownLimit: parseInt(value, 10) })}
          >
            <SelectLabel>{t_i18n('Maximum number of series')}</SelectLabel>
            <SelectTrigger className="w-full">
              <SelectValue />
            </SelectTrigger>
            <SelectContent aria-label={t_i18n('Maximum number of series')}>
              {BREAKDOWN_LIMIT_OPTIONS.map((limit) => (
                <SelectItem key={limit} value={String(limit)}>
                  {limit}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      )}
    </div>
  );
};

export default WidgetBreakdownSelection;
