import { Field, Form, Formik } from 'formik';
import React, { Suspense, useEffect } from 'react';
import ObjectMarkingField from '@components/common/form/ObjectMarkingField';
import InputAdornment from '@mui/material/InputAdornment';
import Button from '@mui/material/Button';
import { Option } from '@components/common/form/ReferenceField';
import { FormikConfig } from 'formik/dist/types';
import * as Yup from 'yup';
import Alert from '@mui/material/Alert';
import { graphql, PreloadedQuery, usePreloadedQuery, useQueryLoader } from 'react-relay';
import MenuItem from '@mui/material/MenuItem';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { PublicDashboardCreationFormDashboardsQuery } from '@components/workspaces/dashboards/public_dashboards/__generated__/PublicDashboardCreationFormDashboardsQuery.graphql';
import { useFormatter } from '../../../../../components/i18n';
import TextField from '../../../../../components/TextField';
import { fieldSpacingContainerStyle } from '../../../../../utils/field';
import SwitchField from '../../../../../components/fields/SwitchField';
import SelectField from '../../../../../components/fields/SelectField';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { handleError, MESSAGING$ } from '../../../../../relay/environment';
import Loader, { LoaderVariant } from '../../../../../components/Loader';
import useAuth from '../../../../../utils/hooks/useAuth';
import { ME_FILTER_VALUE } from '../../../../../utils/filters/filtersUtils';
import { fromB64 } from '../../../../../utils/String';

const publicDashboardCreateMutation = graphql`
  mutation PublicDashboardCreationFormCreateMutation($input: PublicDashboardAddInput!) {
    publicDashboardAdd(input: $input) {
      ...PublicDashboards_PublicDashboard
    }
  }
`;

export const dashboardsQuery = graphql`
  query PublicDashboardCreationFormDashboardsQuery($filters: FilterGroup) {
    workspaces(filters: $filters) {
      edges {
        node {
          id
          name
          currentUserAccessRight
          manifest
        }
      }
    }
  }
`;

export interface PublicDashboardCreationFormData {
  name: string;
  enabled: boolean;
  uri_key: string;
  max_markings: Option[];
  dashboard_id: string;
}

interface PublicDashboardCreationFormComponentProps {
  queryRef: PreloadedQuery<PublicDashboardCreationFormDashboardsQuery>
  dashboard_id?: string
  updater?: (store: RecordSourceSelectorProxy, key: string) => void
  onCancel?: () => void
  onCompleted?: () => void
}

const PublicDashboardCreationFormComponent = ({
  queryRef,
  dashboard_id,
  updater,
  onCancel,
  onCompleted,
}: PublicDashboardCreationFormComponentProps) => {
  const { t_i18n } = useFormatter();
  const { me } = useAuth();
  const publicDashboardCreatorName = me.name;
  const [commitCreateMutation] = useApiMutation(publicDashboardCreateMutation);

  const { workspaces } = usePreloadedQuery(dashboardsQuery, queryRef);
  const dashboards = workspaces?.edges
    .map((edge) => edge.node)
    .filter((dashboard) => dashboard.currentUserAccessRight === 'admin')
    .sort((a, b) => a.name.localeCompare(b.name));

  const dashboardUsingMeFilter = (dashboardId: string) => {
    return (dashboards ?? []).find(({ id, manifest }) => {
      return id === dashboardId && fromB64(manifest ?? '').includes(ME_FILTER_VALUE);
    });
  };

  const formValidation = Yup.object().shape({
    name: Yup.string().required(t_i18n('This field is required')),
    uri_key: Yup.string(),
    enabled: Yup.boolean(),
    max_markings: Yup.array().min(1, 'This field is required').required(t_i18n('This field is required')),
    dashboard_id: Yup.string().required(t_i18n('This field is required')),
  });

  const onSubmit: FormikConfig<PublicDashboardCreationFormData>['onSubmit'] = (values, { setSubmitting, resetForm }) => {
    commitCreateMutation({
      variables: {
        input: {
          name: values.name,
          enabled: values.enabled,
          uri_key: values.uri_key,
          dashboard_id: values.dashboard_id,
          allowed_markings_ids: values.max_markings.map((marking) => marking.value),
        },
      },
      updater: (store) => updater?.(store, 'publicDashboardAdd'),
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        onCompleted?.();
        MESSAGING$.notifySuccess(t_i18n('Public dashboard created'));
      },
      onError: (error) => {
        setSubmitting(false);
        handleError(error);
      },
    });
  };

  return (
    <Formik<PublicDashboardCreationFormData>
      enableReinitialize={true}
      validationSchema={formValidation}
      initialValues={{
        dashboard_id: dashboard_id ?? '',
        name: '',
        enabled: true,
        uri_key: '',
        max_markings: [],
      }}
      onSubmit={onSubmit}
    >
      {({ isSubmitting, isValid, dirty, handleReset, submitForm, setFieldValue, values }) => (
        <Form>
          <Field
            component={SelectField}
            variant="standard"
            name="dashboard_id"
            label={t_i18n('Custom dashboard')}
            fullWidth={true}
            containerstyle={{ width: '100%' }}
            disabled={!!dashboard_id}
          >
            {dashboards?.map((dashboard) => (
              <MenuItem key={dashboard.id} value={dashboard.id}>
                {dashboard.name}
              </MenuItem>
            ))}
          </Field>

          {dashboardUsingMeFilter(values.dashboard_id) && (
            <Alert severity="warning" variant="outlined" style={{ marginTop: 20 }}>
              {t_i18n('A widget has a @me filter enabled...', {
                values: { name: publicDashboardCreatorName },
              })}
            </Alert>
          )}

          <Field
            name="name"
            component={TextField}
            variant="standard"
            label={t_i18n('Name')}
            style={fieldSpacingContainerStyle}
            onChange={(_: string, val: string) => {
              setFieldValue('uri_key', val.replace(/[^a-zA-Z0-9\s-]+/g, '').replace(/\s+/g, '-').toLowerCase());
            }}
          />
          <Field
            disabled
            name="uri_key"
            component={TextField}
            variant="standard"
            label={t_i18n('Public dashboard URI KEY')}
            helperText={t_i18n('ID of your public dashboard')}
            style={fieldSpacingContainerStyle}
            slotProps={{
              input: {
                startAdornment: (
                  <InputAdornment position="start">
                    public/dashboard/
                  </InputAdornment>
                ),
              },
            }}
          />
          <Field
            component={SwitchField}
            type="checkbox"
            name="enabled"
            label={t_i18n('Enabled')}
            containerstyle={fieldSpacingContainerStyle}
            helpertext={t_i18n('Disabled dashboard...')}
          />
          <ObjectMarkingField
            name='max_markings'
            label={t_i18n('Max level markings')}
            helpertext={t_i18n('To prevent people seeing all the data...')}
            style={fieldSpacingContainerStyle}
            onChange={() => {}}
            setFieldValue={setFieldValue}
            limitToMaxSharing
          />
          <Alert severity="info" variant="outlined" style={{ marginTop: '10px' }}>
            {t_i18n('You see only marking definitions that can be shared (defined by the admin)')}
          </Alert>

          <div
            style={{
              ...fieldSpacingContainerStyle,
              display: 'flex',
              justifyContent: 'end',
              gap: '12px',
            }}
          >
            <Button
              variant="contained"
              disabled={isSubmitting}
              onClick={() => {
                handleReset();
                onCancel?.();
              }}
            >
              {t_i18n('Cancel')}
            </Button>
            <Button
              variant="contained"
              color="secondary"
              disabled={isSubmitting || !isValid || !dirty}
              onClick={submitForm}
            >
              {t_i18n('Create')}
            </Button>
          </div>
        </Form>
      )}
    </Formik>
  );
};

type PublicDashboardCreationFormProps = Omit<PublicDashboardCreationFormComponentProps, 'queryRef'>;

const PublicDashboardCreationForm = (props: PublicDashboardCreationFormProps) => {
  const [queryRef, fetchDashboards] = useQueryLoader<PublicDashboardCreationFormDashboardsQuery>(dashboardsQuery);
  const fetchDashboardsWithFilters = () => {
    fetchDashboards(
      {
        filters: {
          mode: 'and',
          filterGroups: [],
          filters: [{
            key: ['type'],
            values: ['dashboard'],
          }],
        },
      },
      { fetchPolicy: 'store-and-network' },
    );
  };

  useEffect(() => {
    fetchDashboardsWithFilters();
  }, []);

  return queryRef && (
    <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <PublicDashboardCreationFormComponent
        queryRef={queryRef}
        {...props}
      />
    </Suspense>
  );
};

export default PublicDashboardCreationForm;
