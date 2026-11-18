import React, { Suspense } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { Select, SelectContent, SelectHelperText, SelectItem, SelectLabel, SelectTrigger, SelectValue } from '@filigran/design-system';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { DashboardPresetFieldQuery } from './__generated__/DashboardPresetFieldQuery.graphql';

const presetsQuery = graphql`
  query DashboardPresetFieldQuery($id: String!) {
    workspace(id: $id) {
      id
      presets {
        id
        name
      }
    }
  }
`;

export interface DashboardPresetFieldProps {
  // The dashboard whose presets are offered: nothing is rendered without one.
  dashboardId: string | null | undefined;
  value: string | null | undefined;
  onChange: (value: string | null) => void;
  label?: string;
  helperText?: string;
  style?: React.CSSProperties;
}

interface DashboardPresetFieldComponentProps extends DashboardPresetFieldProps {
  queryRef: PreloadedQuery<DashboardPresetFieldQuery>;
}

const DashboardPresetFieldComponent = ({ queryRef, value, onChange, label, helperText, style }: DashboardPresetFieldComponentProps) => {
  const { t_i18n } = useFormatter();
  const { workspace } = usePreloadedQuery<DashboardPresetFieldQuery>(presetsQuery, queryRef);
  const presets = workspace?.presets ?? [];
  const fieldLabel = label ?? t_i18n('Default preset');
  // A preset that no longer exists is shown as none.
  const selected = value && presets.some((preset) => preset.id === value) ? value : '';
  return (
    <div style={style} data-testid="dashboard-preset-field">
      <Select
        value={selected}
        // The clear control of the trigger empties the selection: the dashboard opens on its default values.
        onValueChange={(next) => onChange(next === '' ? null : next)}
        clearable
        clearLabel={t_i18n('No preset')}
        name="default_dashboard_preset"
      >
        <SelectLabel>{fieldLabel}</SelectLabel>
        <SelectTrigger className="w-full">
          <SelectValue placeholder={t_i18n('No preset (default values of the dashboard)')} />
        </SelectTrigger>
        <SelectContent aria-label={fieldLabel}>
          {presets.map((preset) => (
            <SelectItem key={preset.id} value={preset.id}>{preset.name}</SelectItem>
          ))}
        </SelectContent>
        <SelectHelperText>{helperText ?? t_i18n('The dashboard opens on the values and time range of this preset')}</SelectHelperText>
      </Select>
    </div>
  );
};

/**
 * The preset a dashboard opens on, among the presets of the selected dashboard. Used wherever a default dashboard is
 * chosen (user, group, organization). Nothing without a dashboard.
 */
const DashboardPresetFieldLoader = (props: DashboardPresetFieldProps & { dashboardId: string }) => {
  const queryRef = useQueryLoading<DashboardPresetFieldQuery>(presetsQuery, { id: props.dashboardId });
  if (!queryRef) return null;
  return (
    <Suspense fallback={null}>
      <DashboardPresetFieldComponent {...props} queryRef={queryRef} />
    </Suspense>
  );
};

const DashboardPresetField = (props: DashboardPresetFieldProps) => {
  const { dashboardId } = props;
  if (!dashboardId) return null;
  return <DashboardPresetFieldLoader {...props} dashboardId={dashboardId} />;
};

export default DashboardPresetField;
