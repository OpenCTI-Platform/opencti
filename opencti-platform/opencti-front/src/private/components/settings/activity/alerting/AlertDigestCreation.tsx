import React, { FunctionComponent } from 'react';
import { graphql, useMutation } from 'react-relay';
import { FormikConfig, FormikHelpers } from 'formik/dist/types';
import { Field, Form, Formik } from 'formik';
import MenuItem from '@mui/material/MenuItem';
import Drawer from '@mui/material/Drawer';
import IconButton from '@mui/material/IconButton';
import { Close } from '@mui/icons-material';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import * as Yup from 'yup';
import makeStyles from '@mui/styles/makeStyles';
import MarkdownField from '../../../../../components/MarkdownField';
import { handleErrorInForm } from '../../../../../relay/environment';
import { insertNode } from '../../../../../utils/store';
import { dayStartDate, parse } from '../../../../../utils/Time';
import { useFormatter } from '../../../../../components/i18n';
import TimePickerField from '../../../../../components/TimePickerField';
import SelectField from '../../../../../components/SelectField';
import { fieldSpacingContainerStyle } from '../../../../../utils/field';
import type { Theme } from '../../../../../components/Theme';
import TextField from '../../../../../components/TextField';
import NotifierField from '../../../common/form/NotifierField';
import AlertsField from './AlertsField';
import { AlertingPaginationQuery$variables } from './__generated__/AlertingPaginationQuery.graphql';
import ObjectMembersField from '../../../common/form/ObjectMembersField';

const useStyles = makeStyles<Theme>((theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
  dialogActions: {
    padding: '0 17px 20px 0',
  },
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
  header: {
    backgroundColor: theme.palette.background.nav,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
}));

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
  const { t } = useFormatter();
  const classes = useStyles();
  const onReset = () => handleClose && handleClose();
  const [commitDigest] = useMutation(triggerDigestCreationMutation);
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
      shouldValidate?: boolean | undefined
    ) => void,
    values: TriggerDigestActivityAddInput,
  ) => (
    <React.Fragment>
      <Field
        component={TextField}
        variant="standard"
        name="name"
        label={t('Name')}
        fullWidth={true}
      />
      <Field
        component={MarkdownField}
        name="description"
        label={t('Description')}
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
        label={t('Period')}
        fullWidth={true}
        containerstyle={fieldSpacingContainerStyle}
      >
        <MenuItem value="hour">{t('hour')}</MenuItem>
        <MenuItem value="day">{t('day')}</MenuItem>
        <MenuItem value="week">{t('week')}</MenuItem>
        <MenuItem value="month">{t('month')}</MenuItem>
      </Field>
      {values.period === 'week' && (
        <Field
          component={SelectField}
          variant="standard"
          name="day"
          label={t('Week day')}
          fullWidth={true}
          containerstyle={fieldSpacingContainerStyle}
        >
          <MenuItem value="1">{t('Monday')}</MenuItem>
          <MenuItem value="2">{t('Tuesday')}</MenuItem>
          <MenuItem value="3">{t('Wednesday')}</MenuItem>
          <MenuItem value="4">{t('Thursday')}</MenuItem>
          <MenuItem value="5">{t('Friday')}</MenuItem>
          <MenuItem value="6">{t('Saturday')}</MenuItem>
          <MenuItem value="7">{t('Sunday')}</MenuItem>
        </Field>
      )}
      {values.period === 'month' && (
        <Field
          component={SelectField}
          variant="standard"
          name="day"
          label={t('Month day')}
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
          TextFieldProps={{
            label: t('Time'),
            variant: 'standard',
            fullWidth: true,
            style: { marginTop: 20 },
          }}
        />
      )}
      <NotifierField name="notifiers" onChange={setFieldValue} />
      <ObjectMembersField
        label={'Recipients'}
        style={fieldSpacingContainerStyle}
        onChange={setFieldValue}
        multiple={true}
        name={'recipients'}
      />
    </React.Fragment>
  );
  const renderClassic = () => (
    <Drawer
      disableRestoreFocus={true}
      open={open}
      anchor="right"
      elevation={1}
      sx={{ zIndex: 1202 }}
      classes={{ paper: classes.drawerPaper }}
      onClose={handleClose}
    >
      <div className={classes.header}>
        <IconButton
          aria-label="Close"
          className={classes.closeButton}
          onClick={handleClose}
          size="large"
          color="primary"
        >
          <Close fontSize="small" color="primary" />
        </IconButton>
        <Typography variant="h6">{t('Create a regular activity digest')}</Typography>
      </div>
      <div className={classes.container}>
        <Formik<TriggerDigestActivityAddInput>
          initialValues={digestInitialValues}
          validationSchema={digestTriggerValidation(t)}
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
            <Form style={{ margin: '20px 0 20px 0' }}>
              {digestFields(setFieldValue, values)}
              <div className={classes.buttons}>
                <Button
                  variant="contained"
                  onClick={handleReset}
                  disabled={isSubmitting}
                  classes={{ root: classes.button }}
                >
                  {t('Cancel')}
                </Button>
                <Button
                  variant="contained"
                  color="secondary"
                  onClick={submitForm}
                  disabled={isSubmitting}
                  classes={{ root: classes.button }}
                >
                  {t('Create')}
                </Button>
              </div>
            </Form>
          )}
        </Formik>
      </div>
    </Drawer>
  );
  const renderContextual = () => (
    <Dialog
      disableRestoreFocus={true}
      open={open ?? false}
      onClose={handleClose}
      PaperProps={{ elevation: 1 }}
    >
      <Formik
        initialValues={digestInitialValues}
        validationSchema={digestTriggerValidation(t)}
        onSubmit={onDigestSubmit}
        onReset={onReset}
      >
        {({ submitForm, handleReset, isSubmitting, setFieldValue, values }) => (
          <div>
            <DialogTitle>{t('Create a regular activity digest')}</DialogTitle>
            <DialogContent>{digestFields(setFieldValue, values)}</DialogContent>
            <DialogActions classes={{ root: classes.dialogActions }}>
              <Button onClick={handleReset} disabled={isSubmitting}>
                {t('Cancel')}
              </Button>
              <Button
                color="secondary"
                onClick={submitForm}
                disabled={isSubmitting}
              >
                {t('Create')}
              </Button>
            </DialogActions>
          </div>
        )}
      </Formik>
    </Dialog>
  );
  return contextual ? renderContextual() : renderClassic();
};

export default AlertDigestCreation;
