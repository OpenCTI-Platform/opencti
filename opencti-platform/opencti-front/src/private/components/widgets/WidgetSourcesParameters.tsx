import React from 'react';
import { Select, SelectContent, SelectItem, SelectLabel, SelectTrigger, SelectValue } from '@filigran/design-system';
import { useFormatter } from '../../../components/i18n';
import useEnterpriseEdition from '../../../utils/hooks/useEnterpriseEdition';
import type { WidgetDataSelection } from '../../../utils/widget/widget';
import { SOURCE_WIDGET_METRICS } from '../integrations/sources/sourceIntelligenceUtils';

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
  value: string;
  onChange: (value: string) => void;
  testId: string;
}

const MetricSelect = ({ label, value, onChange, testId }: MetricSelectProps) => {
  const { t_i18n } = useFormatter();
  const isEnterpriseEdition = useEnterpriseEdition();
  return (
    <div className="mt-5">
      <Select value={value} onValueChange={onChange}>
        <SelectLabel>{label}</SelectLabel>
        <SelectTrigger className="w-full" data-testid={testId}>
          <SelectValue />
        </SelectTrigger>
        <SelectContent aria-label={label}>
          {SOURCE_WIDGET_METRICS.filter((metric) => isEnterpriseEdition || !metric.enterprise).map((metric) => (
            <SelectItem key={metric.key} value={metric.key}>{t_i18n(metric.label)}</SelectItem>
          ))}
        </SelectContent>
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
        value={selection.attribute ?? (isBubble ? 'cost_per_actionable_object' : 'value_score')}
        onChange={(value) => onChange('attribute', value)}
        testId="widget-sources-metric"
      />
      {isBubble && (
        <>
          <MetricSelect
            label={t_i18n('Vertical axis metric')}
            value={selection.field ?? 'impact_score'}
            onChange={(value) => onChange('field', value)}
            testId="widget-sources-y-metric"
          />
          <MetricSelect
            label={t_i18n('Bubble size metric')}
            value={selection.sort_by ?? 'volume_total'}
            onChange={(value) => onChange('sort_by', value)}
            testId="widget-sources-size-metric"
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
          </Select>
        </div>
      )}
    </div>
  );
};

export default WidgetSourcesParameters;
