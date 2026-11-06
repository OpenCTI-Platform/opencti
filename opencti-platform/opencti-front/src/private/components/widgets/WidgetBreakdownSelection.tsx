import React from 'react';
import {
  Alert,
  Icon,
  IconButton,
  Select,
  SelectContent,
  SelectItem,
  SelectLabel,
  SelectTrigger,
  SelectValue,
  Switch,
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from '@filigran/design-system';
import { useFormatter } from '../../../components/i18n';
import { clearBreakdown, getBreakdownLimitOptions, getWidgetBreakdownLimit, getWidgetBreakdownOrder, getWidgetBreakdownOther } from '../../../utils/widget/widgetBreakdown';
import { useWidgetBreakdownState, useWidgetConfigContext } from './WidgetConfigContext';

/**
 * Breakdown choice, made in the parameters step: the fields it offers depend on the perspective and the
 * dataset filters, and a breakdown excludes adding other datasets or counting distinct values.
 * A field the dataset no longer offers is shown as none, and dropped on submit.
 */
const WidgetBreakdownSelection = () => {
  const { t_i18n } = useFormatter();
  const { config, setConfigWidget } = useWidgetConfigContext();
  const { editorState, fieldOptions, resolution, field, unlistedField } = useWidgetBreakdownState();
  const { parameters, perspective } = config.widget;

  // Nothing to choose: a single type without any field to break it down by
  if (editorState === 'hidden' || (fieldOptions.length === 0 && !field)) {
    return null;
  }
  // Several datasets or distinct values: the controls are shown, disabled, with the reason
  const isEditable = editorState === 'editable';

  const setParameters = (changes: Partial<typeof parameters>) => {
    setConfigWidget({ ...config.widget, parameters: { ...config.widget.parameters, ...changes } });
  };

  const fieldSelect = (
    <Select
      value={field ?? 'none'}
      onValueChange={(value: string) => (value === 'none' ? setConfigWidget(clearBreakdown(config.widget)) : setParameters({ breakdownBy: value }))}
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
        {/* The field of the widget, not offered: the type of a single type, or a field kept while the dataset is unknown */}
        {unlistedField && (
          <SelectItem value={unlistedField.key} disabled={resolution !== 'resolved'}>
            {t_i18n(unlistedField.label)}
          </SelectItem>
        )}
      </SelectContent>
    </Select>
  );

  const limitSelect = (
    <Select
      value={String(getWidgetBreakdownLimit(parameters))}
      onValueChange={(value: string) => setParameters({ breakdownLimit: parseInt(value, 10) })}
    >
      <SelectLabel>{t_i18n('Maximum number of series')}</SelectLabel>
      <SelectTrigger className="w-full">
        <SelectValue />
      </SelectTrigger>
      <SelectContent aria-label={t_i18n('Maximum number of series')}>
        {getBreakdownLimitOptions(parameters).map((limit) => (
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
  // The explanation is an info icon next to the label, as for the other fields of the dialog: outside the
  // label of the switch, which a click on would toggle
  const otherSwitch = (
    <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
      <Switch
        checked={getWidgetBreakdownOther(parameters)}
        onCheckedChange={(checked: boolean) => setParameters({ breakdownOther: checked })}
        label={t_i18n('Include Other')}
      />
      <Tooltip>
        <TooltipTrigger asChild>
          <IconButton
            icon={<Icon name="info" size={16} className="text-feedback-info-primary" />}
            aria-label={t_i18n('More information')}
            variant="default"
            priority="tertiary"
            size="sm"
          />
        </TooltipTrigger>
        <TooltipContent>{otherTooltip}</TooltipContent>
      </Tooltip>
    </div>
  );

  const controls = (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', gap: 20 }}>
        <div style={{ flex: 2 }}>{fieldSelect}</div>
        {field && <div style={{ flex: 1 }}>{limitSelect}</div>}
      </div>
      {/* Only a chosen field is checked against the saved filter */}
      {resolution === 'failed' && field && (
        <Alert severity="warning" title={t_i18n('The saved filter could not be read: the breakdown field cannot be checked.')} />
      )}
      {field && (
        <div style={{ display: 'flex', gap: 20, alignItems: 'flex-end' }}>
          <div style={{ flex: 2 }}>{orderSelect}</div>
          <div style={{ flex: 1 }}>{otherSwitch}</div>
        </div>
      )}
    </div>
  );

  return (
    <div style={{ marginTop: 20 }} data-testid="widget-breakdown-selection">
      {isEditable ? controls : (
        <Tooltip>
          <TooltipTrigger asChild>
            {/* FDS-WORKAROUND #68: a disabled library Select cannot trigger its own tooltip, so this div takes the hover and focus — see fds-migration/LIBRARY-FEEDBACK.md #68 */}
            {/* eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex */}
            <div tabIndex={0}>{controls}</div>
          </TooltipTrigger>
          <TooltipContent>
            {editorState === 'distinct-values'
              ? t_i18n('A breakdown counts every event: it cannot count distinct values.')
              : t_i18n('A breakdown uses a single dataset.')}
          </TooltipContent>
        </Tooltip>
      )}
    </div>
  );
};

export default WidgetBreakdownSelection;
