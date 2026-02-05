import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import DialogActions from '@mui/material/DialogActions';
import MenuItem from '@mui/material/MenuItem';
import { Field, Form, Formik } from 'formik';
import { FormikConfig, FormikHelpers } from 'formik/dist/types';
import React, { FunctionComponent } from 'react';
import { graphql } from 'react-relay';
import * as Yup from 'yup';
import FormButtonContainer from '../../../../../components/common/form/FormButtonContainer';
import MarkdownField from '../../../../../components/fields/MarkdownField';
import SelectField from '../../../../../components/fields/SelectField';
import { useFormatter } from '../../../../../components/i18n';
import TextField from '../../../../../components/TextField';
import TimePickerField from '../../../../../components/TimePickerField';
import { handleErrorInForm } from '../../../../../relay/environment';
import { fieldSpacingContainerStyle } from '../../../../../utils/field';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { insertNode } from '../../../../../utils/store';
import { dayStartDate, parse } from '../../../../../utils/Time';
import Drawer from '../../../common/drawer/Drawer';
import NotifierField from '../../../common/form/NotifierField';
import ObjectMembersField from '../../../common/form/ObjectMembersField';
import { AlertingPaginationQuery$variables } from './__generated__/AlertingPaginationQuery.graphql';
import AlertsField from './AlertsField';

const triggerDigestCreationMutation = graphql`
  mutation AlertDigestCreationAddMutation($input: TriggerActivityDigestAddInput!) {
    triggerActivityDigestAdd(input: $input) {
      ...AlertingLine_node
    }
  }
`;

interface TriggerDigestActivityAddInput {
  name: string;
  description: string;
  period: string;
  notifiers: { value: string }[];
  trigger_ids: { value: string }[];
  day: string;
  time: string;
  recipients: { value: string }[];
}

export const digestTriggerValidation = (t: (message: string) => string) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string().nullable(),
  trigger_ids: Yup.array().min(1, t('Minimum one trigger')).required(t('This field is required')),
  period: Yup.string().required(t('This field is required')),
  notifiers: Yup.array().min(1, t('Minimum one notifier')).required(t('This field is required')),
  recipients: Yup.array().min(1, t('Minimum one recipient')).required(t('This field is required')),
  day: Yup.string().nullable(),
  time: Yup.string().nullable(),
});

interface TriggerDigestCreationProps {
  contextual?: boolean;
  open?: boolean;
  handleClose?: () => void;
  inputValue?: string;
  recipientId?: string;
  paginationOptions?: AlertingPaginationQuery$variables;
}

const AlertDigestCreation: FunctionComponent<TriggerDigestCreationProps> = ({
  contextual,
  inputValue,
  paginationOptions,
  open,
  handleClose,
}) => {
  const { t_i18n } = useFormatter();
  const onReset = () => handleClose && handleClose();
  const [commitDigest] = useApiMutation(triggerDigestCreationMutation);
  const digestInitialValues: TriggerDigestActivityAddInput = {
    name: inputValue || '',
    description: '',
    period: 'day',
    trigger_ids: [],
    notifiers: [],
    day: '1',
    time: dayStartDate().toISOString(),
    recipients: [],
  };
  const onDigestSubmit: FormikConfig<TriggerDigestActivityAddInput>['onSubmit'] = (
    values: TriggerDigestActivityAddInput,
    {
      setSubmitting,
      setErrors,
      resetForm,
    }: FormikHelpers<TriggerDigestActivityAddInput>,
  ) => {
    // Important to translate to UTC before formatting
    let triggerTime = `${parse(values.time).utc().format('HH:mm:00.000')}Z`;
    if (values.period !== 'hour' && values.period !== 'day') {
      const day = values.day && values.day.length > 0 ? values.day : '1';
      triggerTime = `${day}-${triggerTime}`;
    }
    const finalValues = {
      name: values.name,
      notifiers: values.notifiers.map(({ value }) => value),
      description: values.description,
      trigger_ids: values.trigger_ids.map(({ value }) => value),
      period: values.period,
      trigger_time: triggerTime,
      recipients: values.recipients.map(({ value }) => value),
    };
    commitDigest({
      variables: {
        input: finalValues,
      },
      updater: (store) => {
        insertNode(store, 'Pagination_triggersActivity', paginationOptions, 'triggerActivityDigestAdd');
      },
      onError: (error: Error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        if (handleClose) {
          handleClose();
        }
      },
    });
  };
  const digestFields = (
    setFieldValue: (
      field: string,
      value: unknown,
      shouldValidate?: boolean | undefined,
    ) => void,
    values: TriggerDigestActivityAddInput,
  ) => (
    <React.Fragment>
      <Field
        component={TextField}
        variant="standard"
        name="name"
        label={t_i18n('Name')}
        fullWidth={true}
      />
      <Field
        component={MarkdownField}
        name="description"
        label={t_i18n('Description')}
        fullWidth={true}
        multiline={true}
        rows="4"
        style={{ marginTop: 20 }}
      />
      <AlertsField
        name="trigger_ids"
        setFieldValue={setFieldValue}
        values={values.trigger_ids}
        style={fieldSpacingContainerStyle}
        paginationOptions={paginationOptions}
      />
      <Field
        component={SelectField}
        variant="standard"
        name="period"
        label={t_i18n('Period')}
        fullWidth={true}
        containerstyle={fieldSpacingContainerStyle}
      >
        <MenuItem value="hour">{t_i18n('hour')}</MenuItem>
        <MenuItem value="day">{t_i18n('day')}</MenuItem>
        <MenuItem value="week">{t_i18n('week')}</MenuItem>
        <MenuItem value="month">{t_i18n('month')}</MenuItem>
      </Field>
      {values.period === 'week' && (
        <Field
          component={SelectField}
          variant="standard"
          name="day"
          label={t_i18n('Week day')}
          fullWidth={true}
          containerstyle={fieldSpacingContainerStyle}
        >
          <MenuItem value="1">{t_i18n('Monday')}</MenuItem>
          <MenuItem value="2">{t_i18n('Tuesday')}</MenuItem>
          <MenuItem value="3">{t_i18n('Wednesday')}</MenuItem>
          <MenuItem value="4">{t_i18n('Thursday')}</MenuItem>
          <MenuItem value="5">{t_i18n('Friday')}</MenuItem>
          <MenuItem value="6">{t_i18n('Saturday')}</MenuItem>
          <MenuItem value="7">{t_i18n('Sunday')}</MenuItem>
        </Field>
      )}
      {values.period === 'month' && (
        <Field
          component={SelectField}
          variant="standard"
          name="day"
          label={t_i18n('Month day')}
          fullWidth={true}
          containerstyle={fieldSpacingContainerStyle}
        >
          {Array.from(Array(31).keys()).map((idx) => (
            <MenuItem key={idx} value={(idx + 1).toString()}>
              {(idx + 1).toString()}
            </MenuItem>
          ))}
        </Field>
      )}
      {values.period !== 'hour' && (
        <Field
          component={TimePickerField}
          name="time"
          withMinutes={true}
          textFieldProps={{
            label: t_i18n('Time'),
            variant: 'standard',
            fullWidth: true,
            style: { marginTop: 20 },
          }}
        />
      )}
      <NotifierField name="notifiers" onChange={setFieldValue} />
      <ObjectMembersField
        label="Recipients"
        style={fieldSpacingContainerStyle}
        onChange={setFieldValue}
        multiple={true}
        name="recipients"
      />
    </React.Fragment>
  );
  const renderClassic = () => (
    <Drawer
      title={t_i18n('Create a regular activity digest')}
      open={open}
      onClose={handleClose}
    >
      <Formik<TriggerDigestActivityAddInput>
        initialValues={digestInitialValues}
        validationSchema={digestTriggerValidation(t_i18n)}
        onSubmit={onDigestSubmit}
        onReset={onReset}
      >
        {({
          submitForm,
          handleReset,
          isSubmitting,
          setFieldValue,
          values,
        }) => (
          <Form>
            {digestFields(setFieldValue, values)}
            <FormButtonContainer>
              <Button
                variant="secondary"
                onClick={handleReset}
                disabled={isSubmitting}
              >
                {t_i18n('Cancel')}
              </Button>
              <Button
                onClick={submitForm}
                disabled={isSubmitting}
              >
                {t_i18n('Create')}
              </Button>
            </FormButtonContainer>
          </Form>
        )}
      </Formik>
    </Drawer>
  );
  const renderContextual = () => (
    <Dialog
      disableRestoreFocus={true}
      open={open ?? false}
      onClose={handleClose}
      title={t_i18n('Create a regular activity digest')}
    >
      <Formik
        initialValues={digestInitialValues}
        validationSchema={digestTriggerValidation(t_i18n)}
        onSubmit={onDigestSubmit}
        onReset={onReset}
      >
        {({ submitForm, handleReset, isSubmitting, setFieldValue, values }) => (
          <>
            {digestFields(setFieldValue, values)}
            <DialogActions>
              <Button
                variant="secondary"
                onClick={handleReset}
                disabled={isSubmitting}
              >
                {t_i18n('Cancel')}
              </Button>
              <Button
                onClick={submitForm}
                disabled={isSubmitting}
              >
                {t_i18n('Create')}
              </Button>
            </DialogActions>
          </>
        )}
      </Formik>
    </Dialog>
  );
  return contextual ? renderContextual() : renderClassic();
};

export default AlertDigestCreation;
