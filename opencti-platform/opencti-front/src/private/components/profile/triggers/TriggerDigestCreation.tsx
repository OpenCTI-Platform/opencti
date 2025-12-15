import { Close } from '@mui/icons-material';
import Button from '@common/button/Button';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import Drawer from '@mui/material/Drawer';
import IconButton from '@common/button/IconButton';
import MenuItem from '@mui/material/MenuItem';
import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import { Field, Form, Formik } from 'formik';
import { FormikConfig, FormikHelpers } from 'formik/dist/types';
import React, { FunctionComponent } from 'react';
import { graphql } from 'react-relay';
import * as Yup from 'yup';
import { useFormatter } from '../../../../components/i18n';
import MarkdownField from '../../../../components/fields/MarkdownField';
import SelectField from '../../../../components/fields/SelectField';
import TextField from '../../../../components/TextField';
import type { Theme } from '../../../../components/Theme';
import TimePickerField from '../../../../components/TimePickerField';
import { handleErrorInForm } from '../../../../relay/environment';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import { insertNode } from '../../../../utils/store';
import { dayStartDate, parse } from '../../../../utils/Time';
import NotifierField from '../../common/form/NotifierField';
import { TriggersLinesPaginationQuery$variables } from './__generated__/TriggersLinesPaginationQuery.graphql';
import TriggersField from './TriggersField';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
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
  mutation TriggerDigestCreationMutation($input: TriggerDigestAddInput!) {
    triggerKnowledgeDigestAdd(input: $input) {
      ...TriggerLine_node
    }
  }
`;

interface TriggerDigestAddInput {
  name: string;
  description: string;
  period: string;
  notifiers: FieldOption[];
  trigger_ids: { value: string }[];
  day: string;
  time: string;
  recipients: string[];
}

const digestTriggerValidation = (t: (message: string) => string) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string().nullable(),
  trigger_ids: Yup.array()
    .min(1, t('Minimum one trigger'))
    .required(t('This field is required')),
  period: Yup.string().required(t('This field is required')),
  notifiers: Yup.array()
    .min(1, t('Minimum one notifier'))
    .required(t('This field is required')),
  day: Yup.string().nullable(),
  time: Yup.string().nullable(),
});

interface TriggerDigestCreationProps {
  contextual?: boolean;
  open?: boolean;
  handleClose?: () => void;
  inputValue?: string;
  recipientId?: string;
  paginationOptions?: TriggersLinesPaginationQuery$variables;
}

const TriggerDigestCreation: FunctionComponent<TriggerDigestCreationProps> = ({
  contextual,
  inputValue,
  paginationOptions,
  open,
  handleClose,
  recipientId,
}) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const onReset = () => handleClose && handleClose();
  const [commitDigest] = useApiMutation(triggerDigestCreationMutation);
  const digestInitialValues: TriggerDigestAddInput = {
    name: inputValue || '',
    description: '',
    period: 'day',
    trigger_ids: [],
    notifiers: [],
    day: '1',
    time: dayStartDate().toISOString(),
    recipients: recipientId ? [recipientId] : [],
  };
  const onDigestSubmit: FormikConfig<TriggerDigestAddInput>['onSubmit'] = (
    values: TriggerDigestAddInput,
    {
      setSubmitting,
      setErrors,
      resetForm,
    }: FormikHelpers<TriggerDigestAddInput>,
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
      recipients: values.recipients,
    };
    commitDigest({
      variables: {
        input: finalValues,
      },
      updater: (store) => {
        insertNode(store, 'Pagination_triggersKnowledge', paginationOptions, 'triggerKnowledgeDigestAdd');
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
    values: TriggerDigestAddInput,
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
      <TriggersField
        name="trigger_ids"
        setFieldValue={setFieldValue}
        values={values.trigger_ids}
        style={fieldSpacingContainerStyle}
        paginationOptions={paginationOptions}
        recipientId={values.recipients[0]}
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
      <NotifierField
        name="notifiers"
        onChange={setFieldValue}
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
          color="primary"
        >
          <Close fontSize="small" color="primary" />
        </IconButton>
        <Typography variant="h6">{t_i18n('Create a regular digest')}</Typography>
      </div>
      <div className={classes.container}>
        <Formik<TriggerDigestAddInput>
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
              <div className={classes.buttons}>
                <Button
                  variant="secondary"
                  onClick={handleReset}
                  disabled={isSubmitting}
                  classes={{ root: classes.button }}
                >
                  {t_i18n('Cancel')}
                </Button>
                <Button
                  onClick={submitForm}
                  disabled={isSubmitting}
                  classes={{ root: classes.button }}
                >
                  {t_i18n('Create')}
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
      slotProps={{ paper: { elevation: 1 } }}
    >
      <Formik
        initialValues={digestInitialValues}
        validationSchema={digestTriggerValidation(t_i18n)}
        onSubmit={onDigestSubmit}
        onReset={onReset}
      >
        {({ submitForm, handleReset, isSubmitting, setFieldValue, values }) => (
          <div>
            <DialogTitle>{t_i18n('Create a regular digest')}</DialogTitle>
            <DialogContent>{digestFields(setFieldValue, values)}</DialogContent>
            <DialogActions classes={{ root: classes.dialogActions }}>
              <Button onClick={handleReset} disabled={isSubmitting}>
                {t_i18n('Cancel')}
              </Button>
              <Button
                color="secondary"
                onClick={submitForm}
                disabled={isSubmitting}
              >
                {t_i18n('Create')}
              </Button>
            </DialogActions>
          </div>
        )}
      </Formik>
    </Dialog>
  );
  return contextual ? renderContextual() : renderClassic();
};

export default TriggerDigestCreation;
