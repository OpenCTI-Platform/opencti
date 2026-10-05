import React from 'react';
import { Select, SelectContent, SelectHelperText, SelectItem, SelectLabel, SelectTrigger, SelectValue } from '@filigran/design-system';
import Button from '@common/button/Button';
import { useFormatter } from '../../../components/i18n';
import useEnterpriseEdition from '../../../utils/hooks/useEnterpriseEdition';
import type { WidgetDataSelection } from '../../../utils/widget/widget';
import { findSourceWidgetMetric, SOURCE_INTELLIGENCE_DOCUMENTATION_URL, sourceWidgetMetricsFor } from '../integrations/sources/sourceIntelligenceUtils';

interface WidgetSourcesParametersProps {
  type: string;
  selection: WidgetDataSelection;
  onChange: (key: keyof WidgetDataSelection, value: string) => void;
}

const AGGREGATION_LABELS: Record<string, string> = {
  avg: 'Average',
  sum: 'Sum',
  min: 'Minimum',
  max: 'Maximum',
  count: 'Number of sources',
};

interface MetricSelectProps {
  label: string;
  help: string;
  value: string;
  onChange: (value: string) => void;
  testId: string;
  widgetType?: string;
}

const MetricSelect = ({ label, help, value, onChange, testId, widgetType }: MetricSelectProps) => {
  const { t_i18n } = useFormatter();
  const isEnterpriseEdition = useEnterpriseEdition();
  return (
    <div className="mt-5">
      <Select value={findSourceWidgetMetric(value, widgetType).key} onValueChange={onChange}>
        <SelectLabel>{label}</SelectLabel>
        <SelectTrigger className="w-full" data-testid={testId}>
          <SelectValue />
        </SelectTrigger>
        <SelectContent aria-label={label}>
          {sourceWidgetMetricsFor(widgetType).filter((metric) => isEnterpriseEdition || !metric.enterprise).map((metric) => (
            <SelectItem key={metric.key} value={metric.key}>{t_i18n(metric.label)}</SelectItem>
          ))}
        </SelectContent>
        <SelectHelperText>{help}</SelectHelperText>
      </Select>
    </div>
  );
};

/**
 * Parameters of a widget of the "Intelligence sources" perspective: the scorecard metric(s) and how they are aggregated or ordered.
 */
const WidgetSourcesParameters = ({ type, selection, onChange }: WidgetSourcesParametersProps) => {
  const { t_i18n } = useFormatter();
  const isBubble = type === 'bubble';
  const isAggregated = type === 'number' || type === 'line';
  const aggregations = type === 'number' ? ['avg', 'sum', 'min', 'max', 'count'] : ['avg', 'sum', 'min', 'max'];
  return (
    <div data-testid="widget-sources-parameters">
      <MetricSelect
        label={isBubble ? t_i18n('Horizontal axis metric') : t_i18n('Metric')}
        help={isBubble
          ? t_i18n('The measure on the horizontal axis, for example the volume. Left empty, it is the cost per actionable object.')
          : t_i18n('The scorecard measure the widget shows, for example the volume. Left empty, it shows the operational value score.')}
        value={selection.attribute ?? (isBubble ? 'cost_per_actionable_object' : 'value_score')}
        onChange={(value) => onChange('attribute', value)}
        testId="widget-sources-metric"
        widgetType={type}
      />
      {isBubble && (
        <>
          <MetricSelect
            label={t_i18n('Vertical axis metric')}
            help={t_i18n('The measure on the vertical axis, for example the accuracy. Left empty, it is the impact score.')}
            value={selection.field ?? 'impact_score'}
            onChange={(value) => onChange('field', value)}
            testId="widget-sources-y-metric"
          />
          <MetricSelect
            label={t_i18n('Bubble size metric')}
            help={t_i18n('The measure that sizes each bubble, for example the unique objects. Left empty, it is the volume.')}
            value={selection.sort_by ?? 'volume_total'}
            onChange={(value) => onChange('sort_by', value)}
            testId="widget-sources-size-metric"
            widgetType="bubble-size"
          />
        </>
      )}
      {isAggregated && (
        <div className="mt-5">
          <Select value={selection.sort_mode && aggregations.includes(selection.sort_mode) ? selection.sort_mode : 'avg'} onValueChange={(value) => onChange('sort_mode', value)}>
            <SelectLabel>{t_i18n('Aggregation over the sources')}</SelectLabel>
            <SelectTrigger className="w-full" data-testid="widget-sources-aggregation">
              <SelectValue />
            </SelectTrigger>
            <SelectContent aria-label={t_i18n('Aggregation over the sources')}>
              {aggregations.map((aggregation) => (
                <SelectItem key={aggregation} value={aggregation}>{t_i18n(AGGREGATION_LABELS[aggregation])}</SelectItem>
              ))}
            </SelectContent>
            <SelectHelperText>
              {type === 'number'
                ? t_i18n('How the values of the scored sources are combined, for example their sum, or Number of sources to count them. Left empty, their average is shown.')
                : t_i18n('How the values of the scored sources are combined on each day, for example their maximum. Left empty, their average is drawn.')}
            </SelectHelperText>
          </Select>
        </div>
      )}
      {!isAggregated && !isBubble && type !== 'list' && (
        <div className="mt-5">
          <Select value={selection.sort_mode === 'asc' ? 'asc' : 'desc'} onValueChange={(value) => onChange('sort_mode', value)}>
            <SelectLabel>{t_i18n('Sort mode')}</SelectLabel>
            <SelectTrigger className="w-full">
              <SelectValue />
            </SelectTrigger>
            <SelectContent aria-label={t_i18n('Sort mode')}>
              <SelectItem value="desc">{t_i18n('Highest first')}</SelectItem>
              <SelectItem value="asc">{t_i18n('Lowest first')}</SelectItem>
            </SelectContent>
            <SelectHelperText>{t_i18n('The order of the sources, for example the lowest values first. Left empty, the highest values come first.')}</SelectHelperText>
          </Select>
        </div>
      )}
      <div className="mt-3">
        <Button variant="tertiary" size="small" component="a" href={`${SOURCE_INTELLIGENCE_DOCUMENTATION_URL}#dashboards`} target="_blank" rel="noopener noreferrer">
          {t_i18n('Learn more')}
        </Button>
      </div>
    </div>
  );
};

export default WidgetSourcesParameters;
