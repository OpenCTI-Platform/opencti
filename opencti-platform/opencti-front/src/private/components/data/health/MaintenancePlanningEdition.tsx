import React, { FunctionComponent, Suspense, useCallback, useState } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import Button from '@mui/material/Button';
import Typography from '@mui/material/Typography';
import { ContentCopyOutlined, EditOutlined } from '@mui/icons-material';
import * as Yup from 'yup';
import Drawer from '../../common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import TextField from '../../../../components/TextField';
import { handleErrorInForm } from '../../../../relay/environment';
import { MaintenancePlanningEditionQuery } from './__generated__/MaintenancePlanningEditionQuery.graphql';

const maintenancePlanningQuery = graphql`
  query MaintenancePlanningEditionQuery {
    dataSanityConfiguration {
      id
      maintenance_planning {
        day
        start_time
        end_time
      }
    }
  }
`;

const maintenancePlanningMutation = graphql`
  mutation MaintenancePlanningEditionMutation($planning: [DataSanityMaintenanceWindowInput!]!) {
    dataSanityUpdateMaintenancePlanning(planning: $planning) {
      id
      maintenance_planning {
        day
        start_time
        end_time
      }
    }
  }
`;

const DAYS_OF_WEEK = [
  { value: 'monday', label: 'Monday' },
  { value: 'tuesday', label: 'Tuesday' },
  { value: 'wednesday', label: 'Wednesday' },
  { value: 'thursday', label: 'Thursday' },
  { value: 'friday', label: 'Friday' },
  { value: 'saturday', label: 'Saturday' },
  { value: 'sunday', label: 'Sunday' },
];

const TIME_REGEX = /^([01]\d|2[0-3]):([0-5]\d)$/;

const maintenancePlanningValidation = (t: (arg: string) => string) => Yup.object().shape(
  Object.fromEntries(DAYS_OF_WEEK.flatMap((d) => [
    [`${d.value}_start_time`, Yup.string().matches(TIME_REGEX, t('Invalid time format (HH:mm)'))],
    [`${d.value}_end_time`, Yup.string().matches(TIME_REGEX, t('Invalid time format (HH:mm)'))],
  ])),
);

type FormValues = Record<string, string>;

const buildInitialValues = (planning: ReadonlyArray<{ readonly day: string; readonly start_time: string; readonly end_time: string }>): FormValues => {
  const values: FormValues = {};
  for (const day of DAYS_OF_WEEK) {
    const existing = planning.find((w) => w.day === day.value);
    values[`${day.value}_start_time`] = existing?.start_time ?? '';
    values[`${day.value}_end_time`] = existing?.end_time ?? '';
  }
  return values;
};

const formValuesToPlanning = (values: FormValues) => {
  return DAYS_OF_WEEK
    .filter((d) => values[`${d.value}_start_time`] && values[`${d.value}_end_time`])
    .map((d) => ({
      day: d.value,
      start_time: values[`${d.value}_start_time`],
      end_time: values[`${d.value}_end_time`],
    }));
};

interface MaintenancePlanningFormProps {
  onClose: () => void;
}

const MaintenancePlanningForm: FunctionComponent<MaintenancePlanningFormProps> = ({ onClose }) => {
  const { t_i18n } = useFormatter();

  const data = useLazyLoadQuery<MaintenancePlanningEditionQuery>(
    maintenancePlanningQuery,
    {},
    { fetchPolicy: 'network-only' },
  );

  const currentPlanning = data.dataSanityConfiguration?.maintenance_planning ?? [];
  const initialValues = buildInitialValues(currentPlanning);

  const [commitMutation] = useApiMutation(maintenancePlanningMutation);

  const onSubmit = useCallback((
    values: FormValues,
    { setSubmitting, setErrors }: { setSubmitting: (flag: boolean) => void; setErrors: (errors: Record<string, string>) => void },
  ) => {
    const planning = formValuesToPlanning(values);
    commitMutation({
      variables: { planning },
      onCompleted: () => {
        setSubmitting(false);
        onClose();
      },
      onError: (error: Error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
    });
  }, [commitMutation, onClose]);

  return (
    <Formik
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={maintenancePlanningValidation(t_i18n)}
      onSubmit={onSubmit}
    >
      {({ submitForm, isSubmitting, values, setFieldValue }) => (
        <Form>
          <Typography variant="body2" sx={{ mb: 2 }}>
            {t_i18n('Define the maintenance windows during which data sanity operations are allowed to run. If no window is configured, operations will run at any time.')}
          </Typography>
          <Typography variant="caption" color="text.secondary" sx={{ mb: 2, display: 'block' }}>
            {t_i18n('Leave both start and end empty to disable the window for a given day.')}
          </Typography>
          {DAYS_OF_WEEK.map((day) => (
            <div key={day.value} style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 15 }}>
              <Typography variant="body2" sx={{ minWidth: 100, fontWeight: 500 }}>
                {t_i18n(day.label)}
              </Typography>
              <Field
                component={TextField}
                name={`${day.value}_start_time`}
                label={t_i18n('Start (HH:mm)')}
                style={{ flex: 1 }}
                placeholder="00:00"
              />
              <Field
                component={TextField}
                name={`${day.value}_end_time`}
                label={t_i18n('End (HH:mm)')}
                style={{ flex: 1 }}
                placeholder="23:59"
              />
            </div>
          ))}
          <div style={{ marginTop: 20, display: 'flex', justifyContent: 'space-between' }}>
            <Button
              variant="outlined"
              size="small"
              startIcon={<ContentCopyOutlined />}
              onClick={() => {
                const mondayStart = values.monday_start_time;
                const mondayEnd = values.monday_end_time;
                DAYS_OF_WEEK.forEach((day) => {
                  if (day.value !== 'monday') {
                    setFieldValue(`${day.value}_start_time`, mondayStart);
                    setFieldValue(`${day.value}_end_time`, mondayEnd);
                  }
                });
              }}
            >
              {t_i18n('Copy Monday to all days')}
            </Button>
            <Button
              variant="contained"
              color="secondary"
              onClick={submitForm}
              disabled={isSubmitting}
            >
              {t_i18n('Update')}
            </Button>
          </div>
        </Form>
      )}
    </Formik>
  );
};

const MaintenancePlanningEdition: FunctionComponent = () => {
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState(false);

  const handleOpen = () => setOpen(true);
  const handleClose = () => setOpen(false);

  return (
    <>
      <Button
        variant="outlined"
        size="small"
        startIcon={<EditOutlined />}
        onClick={handleOpen}
        sx={{ marginBottom: 2 }}
      >
        {t_i18n('Maintenance planning')}
      </Button>
      <Drawer
        open={open}
        onClose={handleClose}
        title={t_i18n('Edit maintenance planning')}
      >
        {open ? (
          <Suspense fallback={<div />}>
            <MaintenancePlanningForm onClose={handleClose} />
          </Suspense>
        ) : null}
      </Drawer>
    </>
  );
};

export default MaintenancePlanningEdition;
