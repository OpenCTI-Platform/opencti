import { Close } from '@mui/icons-material';
import IconButton from '@common/button/IconButton';
import MenuItem from '@mui/material/MenuItem';
import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import { Field, Form, Formik } from 'formik';
import { FormikConfig } from 'formik/dist/types';
import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import { useFormatter } from '../../../../../components/i18n';
import MarkdownField from '../../../../../components/fields/MarkdownField';
import SelectField from '../../../../../components/fields/SelectField';
import TextField from '../../../../../components/TextField';
import type { Theme } from '../../../../../components/Theme';
import TimePickerField from '../../../../../components/TimePickerField';
import { convertNotifiers, convertTriggers } from '../../../../../utils/edition';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../../utils/field';
import { dayStartDate, parse } from '../../../../../utils/Time';
import ObjectMembersField from '../../../common/form/ObjectMembersField';
import NotifierField from '../../../common/form/NotifierField';
import { AlertDigestEdition_trigger$key } from './__generated__/AlertDigestEdition_trigger.graphql';
import { AlertEditionQuery } from './__generated__/AlertEditionQuery.graphql';
import { AlertingPaginationQuery$variables } from './__generated__/AlertingPaginationQuery.graphql';
import { digestTriggerValidation } from './AlertDigestCreation';
import { alertEditionQuery } from './AlertEditionQuery';
import AlertsField from './AlertsField';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';

interface AlertDigestEditionProps {
  handleClose: () => void;
  paginationOptions?: AlertingPaginationQuery$variables;
  queryRef: PreloadedQuery<AlertEditionQuery>;
}

interface AlertDigestFormValues {
  name?: string;
  notifiers: FieldOption[];
  recipients: FieldOption[];
  trigger_ids: { value: string }[];
  period: string;
}

const alertDigestEditionFragment = graphql`
  fragment AlertDigestEdition_trigger on Trigger {
    id
    name
    trigger_type
    event_types
    description
    filters
    notifiers{
      id
      name
    }
    trigger_time
    period
    recipients {
      id
      name
    }
    triggers {
      id
      name
    }
  }
`;

const alertDigestEditionFieldPatch = graphql`
  mutation AlertDigestEditionFieldPatchMutation(
    $id: ID!
    $input: [EditInput!]!
  ) {
    triggerActivityFieldPatch(id: $id, input: $input) {
      ...AlertDigestEdition_trigger
    }
  }
`;

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
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
  title: {
    float: 'left',
  },
}));

const AlertDigestEdition: FunctionComponent<AlertDigestEditionProps> = ({ queryRef, paginationOptions, handleClose }) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const data = usePreloadedQuery<AlertEditionQuery>(alertEditionQuery, queryRef);
  const trigger = useFragment<AlertDigestEdition_trigger$key>(alertDigestEditionFragment, data.triggerKnowledge);
  const [commitFieldPatch] = useApiMutation(alertDigestEditionFieldPatch);
  const onSubmit: FormikConfig<AlertDigestFormValues>['onSubmit'] = (values, { setSubmitting }) => {
    commitFieldPatch({
      variables: {
        id: trigger?.id,
        input: values,
      },
      onCompleted: () => {
        setSubmitting(false);
        handleClose();
      },
    });
  };
  const handleSubmitField = (name: string, value: FieldOption | string | string[]) => {
    return digestTriggerValidation(t_i18n).validateAt(name, { [name]: value }).then(() => {
      commitFieldPatch({
        variables: {
          id: trigger?.id,
          input: { key: name, value: value || '' },
        },
      });
    }).catch(() => false);
  };
  const handleSubmitFieldOptions = (name: string, value: { value: string }[]) => digestTriggerValidation(t_i18n)
    .validateAt(name, { [name]: value })
    .then(() => {
      commitFieldPatch({
        variables: {
          id: trigger?.id,
          input: { key: name, value: value?.map(({ value: v }) => v) ?? '' },
        },
      });
    })
    .catch(() => false);
  const handleSubmitDay = (_: string, value: string) => {
    const day = value && value.length > 0 ? value : '1';
    const currentTime = trigger?.trigger_time?.split('-') ?? [
      `${parse(dayStartDate()).utc().format('HH:mm:00.000')}Z`,
    ];
    const newTime = currentTime.length > 1
      ? `${day}-${currentTime[1]}`
      : `${day}-${currentTime[0]}`;
    return commitFieldPatch({
      variables: {
        id: trigger?.id,
        input: { key: 'trigger_time', value: newTime },
      },
    });
  };
  const handleSubmitTime = (_: string, value: string) => {
    const time = value && value.length > 0
      ? `${parse(value).utc().format('HH:mm:00.000')}Z`
      : `${parse(dayStartDate()).utc().format('HH:mm:00.000')}Z`;
    const currentTime = trigger?.trigger_time?.split('-') ?? [
      `${parse(dayStartDate()).utc().format('HH:mm:00.000')}Z`,
    ];
    const newTime = currentTime.length > 1 && trigger?.period !== 'hour'
      ? `${currentTime[0]}-${time}`
      : time;
    return commitFieldPatch({
      variables: {
        id: trigger?.id,
        input: { key: 'trigger_time', value: newTime },
      },
    });
  };

  const currentTime = trigger?.trigger_time?.split('-') ?? [dayStartDate().toISOString()];
  const initialValues = {
    name: trigger?.name,
    description: trigger?.description,
    notifiers: convertNotifiers(trigger),
    trigger_ids: convertTriggers(trigger),
    recipients: (trigger?.recipients ?? []).map((n) => ({ label: n?.name, value: n?.id })),
    period: trigger?.period,
    day: currentTime.length > 1 ? currentTime[0] : '1',
    time: currentTime.length > 1 ? `2000-01-01T${currentTime[1]}` : `2000-01-01T${currentTime[0]}`,
  };

  return (
    <div>
      <div className={classes.header}>
        <IconButton
          aria-label="Close"
          className={classes.closeButton}
          onClick={handleClose}
          color="primary"
        >
          <Close fontSize="small" color="primary" />
        </IconButton>
        <Typography variant="h6" classes={{ root: classes.title }}>
          {t_i18n('Update an activity digest trigger')}
        </Typography>
        <div className="clearfix" />
      </div>
      <div className={classes.container}>
        <Formik enableReinitialize={true} initialValues={initialValues as never} onSubmit={onSubmit}>
          {({ values, setFieldValue }) => (
            <Form>
              <Field
                component={TextField}
                variant="standard"
                name="name"
                label={t_i18n('Name')}
                fullWidth={true}
                onSubmit={handleSubmitField}
              />
              <Field
                component={MarkdownField}
                name="description"
                label={t_i18n('Description')}
                fullWidth={true}
                multiline={true}
                rows="4"
                onSubmit={handleSubmitField}
                style={{ marginTop: 20 }}
              />
              <AlertsField
                name="trigger_ids"
                setFieldValue={setFieldValue}
                values={values.trigger_ids}
                style={fieldSpacingContainerStyle}
                onChange={handleSubmitFieldOptions}
                paginationOptions={paginationOptions}
              />
              <Field
                component={SelectField}
                variant="standard"
                name="period"
                label={t_i18n('Period')}
                fullWidth={true}
                containerstyle={fieldSpacingContainerStyle}
                onChange={handleSubmitField}
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
                  onChange={handleSubmitDay}
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
                  onChange={handleSubmitDay}
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
                  onSubmit={handleSubmitTime}
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
                onChange={(name, v) => handleSubmitField(name, v.map(({ value }) => value))}
              />
              <ObjectMembersField
                label="Recipients"
                style={fieldSpacingContainerStyle}
                onChange={handleSubmitFieldOptions}
                multiple={true}
                name="recipients"
              />
            </Form>
          )}
        </Formik>
      </div>
    </div>

  );
};

export default AlertDigestEdition;
