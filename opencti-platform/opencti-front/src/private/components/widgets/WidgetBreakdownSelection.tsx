import React, { useEffect } from 'react';
import { Select, SelectContent, SelectItem, SelectLabel, SelectTrigger, SelectValue, Switch, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { useFormatter } from '../../../components/i18n';
import {
  BREAKDOWN_LIMIT_OPTIONS,
  getWidgetBreakdownLimit,
  getWidgetBreakdownLockReason,
  getWidgetBreakdownOrder,
  getWidgetBreakdownOther,
  isBreakdownField,
  isWidgetBreakdownConfigurable,
} from '../../../utils/widget/widgetBreakdown';
import { useWidgetConfigContext } from './WidgetConfigContext';
import useWidgetBreakdownFieldOptions from './useWidgetBreakdownFieldOptions';

// Cleared together with the field: they only make sense for a broken down widget
const NO_BREAKDOWN = { breakdownBy: null, breakdownLimit: null, breakdownOrder: null, breakdownOther: null };

/**
 * Breakdown choice, made in the parameters step: the fields it offers depend on the perspective and the
 * dataset filters, and a breakdown excludes adding other datasets or counting distinct values.
 */
const WidgetBreakdownSelection = () => {
  const { t_i18n } = useFormatter();
  const { config, setConfigWidget, host } = useWidgetConfigContext();
  const { dataSelection, parameters, perspective } = config.widget;

  const isSupported = isWidgetBreakdownConfigurable(config.widget, host);
  // Several datasets or distinct values: the controls are shown, disabled, with the reason
  const lockReason = getWidgetBreakdownLockReason(config.widget);
  const isEditable = !lockReason;
  const { fieldOptions, isResolved } = useWidgetBreakdownFieldOptions({ perspective, dataSelection }, isSupported);
  const breakdownBy = isBreakdownField(parameters.breakdownBy) ? parameters.breakdownBy : null;
  const isFieldAvailable = fieldOptions.some(({ key }) => key === breakdownBy);

  const setParameters = (changes: Partial<typeof parameters>) => {
    setConfigWidget({ ...config.widget, parameters: { ...config.widget.parameters, ...changes } });
  };

  // Filters changed to types without this field: drop the breakdown rather than keeping a field the API refuses.
  // Not before the saved filter is read: its types are unknown until then.
  useEffect(() => {
    if (isEditable && isResolved && breakdownBy && !isFieldAvailable) {
      setParameters(NO_BREAKDOWN);
    }
  }, [isEditable, isResolved, breakdownBy, isFieldAvailable]);

  if (!isSupported) {
    return null;
  }

  // A field set next to several datasets or distinct values is kept visible, but nothing can be changed
  const hasField = !!breakdownBy && (isFieldAvailable || !isEditable);

  const fieldSelect = (
    <Select
      value={isFieldAvailable && breakdownBy ? breakdownBy : 'none'}
      onValueChange={(value: string) => setParameters(value === 'none' ? NO_BREAKDOWN : { breakdownBy: value })}
      disabled={!isEditable}
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

  const limitSelect = (
    <Select
      value={String(getWidgetBreakdownLimit(parameters))}
      onValueChange={(value: string) => setParameters({ breakdownLimit: parseInt(value, 10) })}
      disabled={!isEditable}
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
  );

  const orderSelect = (
    <Select
      value={getWidgetBreakdownOrder(parameters)}
      onValueChange={(value: string) => setParameters({ breakdownOrder: value === 'asc' ? 'asc' : 'desc' })}
      disabled={!isEditable}
    >
      <SelectLabel>{t_i18n('Order')}</SelectLabel>
      <SelectTrigger className="w-full">
        <SelectValue />
      </SelectTrigger>
      <SelectContent aria-label={t_i18n('Order')}>
        <SelectItem value="desc">{t_i18n('Highest values')}</SelectItem>
        <SelectItem value="asc">{t_i18n('Lowest values')}</SelectItem>
      </SelectContent>
    </Select>
  );

  // What the Other series groups: entities, relationships or events
  let otherTooltip = t_i18n('Groups the entities that have none of the displayed values, including entities without a value.');
  if (perspective === 'relationships') {
    otherTooltip = t_i18n('Groups the relationships that have none of the displayed values, including relationships without a value.');
  } else if (perspective === 'audits') {
    otherTooltip = t_i18n('Groups the events that have none of the displayed values, including events without a value.');
  }
  const otherSwitch = (
    <div style={{ width: 'fit-content' }}>
      <Switch
        checked={getWidgetBreakdownOther(parameters)}
        onCheckedChange={(checked: boolean) => setParameters({ breakdownOther: checked })}
        disabled={!isEditable}
        label={t_i18n('Include Other')}
      />
    </div>
  );

  const controls = (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', gap: 20 }}>
        <div style={{ flex: 2 }}>{fieldSelect}</div>
        {hasField && <div style={{ flex: 1 }}>{limitSelect}</div>}
      </div>
      {hasField && (
        <div style={{ display: 'flex', gap: 20, alignItems: 'flex-end' }}>
          <div style={{ flex: 2 }}>{orderSelect}</div>
          <div style={{ flex: 1 }}>
            {isEditable ? (
              <Tooltip>
                <TooltipTrigger asChild>{otherSwitch}</TooltipTrigger>
                <TooltipContent>
                  {otherTooltip}
                </TooltipContent>
              </Tooltip>
            ) : otherSwitch}
          </div>
        </div>
      )}
    </div>
  );

  return (
    <div style={{ marginTop: 20 }} data-testid="widget-breakdown-selection">
      {isEditable ? controls : (
        <Tooltip>
          <TooltipTrigger asChild>
            {/* Disabled controls get no pointer events: the wrapper carries the tooltip */}
            {/* eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex */}
            <div tabIndex={0}>{controls}</div>
          </TooltipTrigger>
          <TooltipContent>
            {lockReason === 'distinct-values'
              ? t_i18n('A breakdown counts every event: it cannot count distinct values.')
              : t_i18n('A breakdown uses a single dataset.')}
          </TooltipContent>
        </Tooltip>
      )}
    </div>
  );
};

export default WidgetBreakdownSelection;
