import { Field, Form, Formik } from 'formik';
import { FormikConfig } from 'formik/dist/types';
import { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import MarkdownField from '../../../../../components/fields/markdownField/MarkdownField';
import SelectFieldFds, { SelectItem } from '../../../../../components/fields/SelectFieldFds';
import { useFormatter } from '../../../../../components/i18n';
import TextField from '../../../../../components/TextField';
import TimePickerField from '../../../../../components/TimePickerField';
import { convertNotifiers, convertTriggers } from '../../../../../utils/edition';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../../utils/field';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { dayStartDate, parse } from '../../../../../utils/Time';
import NotifierField from '../../../common/form/NotifierField';
import ObjectMembersField from '../../../common/form/ObjectMembersField';
import { AlertDigestEdition_trigger$key } from './__generated__/AlertDigestEdition_trigger.graphql';
import { AlertEditionQuery } from './__generated__/AlertEditionQuery.graphql';
import { AlertingPaginationQuery$variables } from './__generated__/AlertingPaginationQuery.graphql';
import { digestTriggerValidation } from './AlertDigestCreation';
import { alertEditionQuery } from './AlertEditionQuery';
import AlertsField from './AlertsField';

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

const AlertDigestEdition: FunctionComponent<AlertDigestEditionProps> = ({ queryRef, paginationOptions, handleClose }) => {
  const { t_i18n } = useFormatter();
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
    <Formik enableReinitialize={true} initialValues={initialValues as never} onSubmit={onSubmit}>
      {({ values, setFieldValue }) => (
        <Form>
          <Field
            component={TextField}
            variant="outlined"
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
            component={SelectFieldFds}
            variant="outlined"
            name="period"
            label={t_i18n('Period')}
            fullWidth={true}
            containerstyle={fieldSpacingContainerStyle}
            onChange={handleSubmitField}
          >
            <SelectItem value="hour">{t_i18n('hour')}</SelectItem>
            <SelectItem value="day">{t_i18n('day')}</SelectItem>
            <SelectItem value="week">{t_i18n('week')}</SelectItem>
            <SelectItem value="month">{t_i18n('month')}</SelectItem>
          </Field>
          {values.period === 'week' && (
            <Field
              component={SelectFieldFds}
              variant="outlined"
              name="day"
              label={t_i18n('Week day')}
              fullWidth={true}
              containerstyle={fieldSpacingContainerStyle}
              onChange={handleSubmitDay}
            >
              <SelectItem value="1">{t_i18n('Monday')}</SelectItem>
              <SelectItem value="2">{t_i18n('Tuesday')}</SelectItem>
              <SelectItem value="3">{t_i18n('Wednesday')}</SelectItem>
              <SelectItem value="4">{t_i18n('Thursday')}</SelectItem>
              <SelectItem value="5">{t_i18n('Friday')}</SelectItem>
              <SelectItem value="6">{t_i18n('Saturday')}</SelectItem>
              <SelectItem value="7">{t_i18n('Sunday')}</SelectItem>
            </Field>
          )}
          {values.period === 'month' && (
            <Field
              component={SelectFieldFds}
              variant="outlined"
              name="day"
              label={t_i18n('Month day')}
              fullWidth={true}
              containerstyle={fieldSpacingContainerStyle}
              onChange={handleSubmitDay}
            >
              {Array.from(Array(31).keys()).map((idx) => (
                <SelectItem key={idx} value={(idx + 1).toString()}>
                  {(idx + 1).toString()}
                </SelectItem>
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
                variant: 'outlined',
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

  );
};

export default AlertDigestEdition;
