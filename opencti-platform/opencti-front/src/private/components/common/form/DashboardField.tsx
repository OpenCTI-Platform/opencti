import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import { useFormikContext } from 'formik';
import AutocompleteField, { AutocompleteFieldProps } from '../../../../components/AutocompleteField';
import { useFormatter } from '../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { SubscriptionFocus } from '../../../../components/Subscription';
import Field, { fieldSpacingContainerStyle } from '../../../../utils/field';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { DashboardFieldQuery } from './__generated__/DashboardFieldQuery.graphql';
import ItemIcon from '../../../../components/ItemIcon';
import { GenericContext } from '../model/GenericContextModel';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  icon: {
    paddingTop: 4,
    display: 'inline-block',
  },
  text: {
    display: 'inline-block',
    flexGrow: 1,
    marginLeft: 10,
  },
}));

interface DashboardFieldProps {
  onChange: (name: string, value: string) => void;
  context?: readonly (GenericContext | null)[] | null;
  queryRef: PreloadedQuery<DashboardFieldQuery>;
  includePresetSelector?: boolean;
}

interface FormOptionValue {
  value: string;
  label: string;
}

interface DashboardFieldFormValues {
  default_dashboard?: FormOptionValue | null;
  default_dashboard_preset_id?: FormOptionValue | null;
}

const workspaceQuery = graphql`
  query DashboardFieldQuery {
    workspaces(filters: { mode: and, filters: [{ key: "type", values: ["Dashboard"] }], filterGroups: [] }) {
      edges {
        node {
          id
          name
          presets {
            id
            name
          }
        }
      }
    }
  }
`;

const DashboardFieldComponent: FunctionComponent<DashboardFieldProps> = ({
  onChange,
  context,
  queryRef,
  includePresetSelector = false,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const { values, setFieldValue } = useFormikContext<DashboardFieldFormValues>();
  const { workspaces } = usePreloadedQuery<DashboardFieldQuery>(
    workspaceQuery,
    queryRef,
  );
  const workspaceOptions = (workspaces?.edges ?? []).map(({ node: { id, name, presets } }) => ({
    value: id,
    label: name,
    type: 'Dashboard',
    presets: presets ?? [],
  }));
  const selectedDashboardId = values.default_dashboard?.value;
  const selectedDashboard = workspaceOptions.find((workspace) => workspace.value === selectedDashboardId);
  const presetOptions = (selectedDashboard?.presets ?? []).map((preset) => ({
    value: preset.id,
    label: preset.name,
    type: 'DashboardPreset',
  }));

  const onDashboardChange = (_name: string, value: { value: string } | null) => {
    onChange('default_dashboard', value?.value ?? '');
    if (!includePresetSelector) {
      return;
    }
    const nextDashboardId = value?.value;
    const nextDashboard = workspaceOptions.find((workspace) => workspace.value === nextDashboardId);
    const allowedPresetIds = new Set((nextDashboard?.presets ?? []).map((preset) => preset.id));
    const currentPresetId = values.default_dashboard_preset_id?.value;
    if (!currentPresetId || allowedPresetIds.has(currentPresetId)) {
      return;
    }
    setFieldValue('default_dashboard_preset_id', null);
    onChange('default_dashboard_preset_id', '');
  };

  return (
    <>
      <Field<AutocompleteFieldProps<false>>
        component={AutocompleteField}
        name="default_dashboard"
        multiple={false}
        onChange={onDashboardChange}
        isOptionEqualToValue={(option, { value }) => option.value === value}
        textfieldprops={{
          variant: 'standard',
          label: t_i18n('Default dashboard'),
          fullWidth: true,
          helperText: (
            <SubscriptionFocus context={context} fieldName="default_dashboard" />
          ),
        }}
        options={workspaceOptions}
        style={fieldSpacingContainerStyle}
        renderOption={(props, option) => (
          <li {...props}>
            <div className={classes.icon} style={{ color: option.color }}>
              <ItemIcon type={option.type} />
            </div>
            <div className={classes.text}>{option.label}</div>
          </li>
        )}
      />
      {includePresetSelector && (
        <Field<AutocompleteFieldProps<false>>
          component={AutocompleteField}
          name="default_dashboard_preset_id"
          multiple={false}
          onChange={(name, value) => onChange(name, value?.value ?? '')}
          isOptionEqualToValue={(option, { value }) => option.value === value}
          textfieldprops={{
            variant: 'standard',
            label: t_i18n('Preset'),
            fullWidth: true,
            helperText: (
              <>
                <SubscriptionFocus context={context} fieldName="default_dashboard_preset_id" />
                {selectedDashboardId && presetOptions.length === 0
                  ? t_i18n('No presets available for the selected dashboard.')
                  : ''}
              </>
            ),
          }}
          options={presetOptions}
          style={fieldSpacingContainerStyle}
          disabled={!selectedDashboardId}
          renderOption={(props, option) => (
            <li {...props}>
              <div className={classes.icon} style={{ color: option.color }}>
                <ItemIcon type={option.type} />
              </div>
              <div className={classes.text}>{option.label}</div>
            </li>
          )}
        />
      )}
    </>
  );
};

const DashboardField: FunctionComponent<
  Omit<DashboardFieldProps, 'queryRef'>
> = (props) => {
  const queryRef = useQueryLoading<DashboardFieldQuery>(workspaceQuery);
  return queryRef ? (
    <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <DashboardFieldComponent {...props} queryRef={queryRef} />
    </React.Suspense>
  ) : (
    <Loader variant={LoaderVariant.inElement} />
  );
};

export default DashboardField;
