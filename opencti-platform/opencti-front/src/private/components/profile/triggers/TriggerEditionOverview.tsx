import React, { FunctionComponent, useState } from 'react';
import { graphql, useFragment, useMutation } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import MenuItem from '@mui/material/MenuItem';
import { FormikConfig } from 'formik/dist/types';
import * as R from 'ramda';
import Checkbox from '@mui/material/Checkbox';
import ListItemText from '@mui/material/ListItemText';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { Option } from '../../common/form/ReferenceField';
import { TriggerEditionOverview_trigger$key } from './__generated__/TriggerEditionOverview_trigger.graphql';
import MarkdownField from '../../../../components/MarkdownField';
import SelectField from '../../../../components/SelectField';
import Filters from '../../common/lists/Filters';
import { isUniqFilter } from '../../../../utils/filters/filtersUtils';
import { convertEventTypes, convertOutcomes, convertTriggers } from '../../../../utils/edition';
import { TriggersLinesPaginationQuery$variables } from './__generated__/TriggersLinesPaginationQuery.graphql';
import TriggersField from './TriggersField';
import TimePickerField from '../../../../components/TimePickerField';
import { dayStartDate, parse } from '../../../../utils/Time';
import FilterIconButton from '../../../../components/FilterIconButton';
import FilterAutocomplete from '../../common/lists/FilterAutocomplete';
import AutocompleteField from '../../../../components/AutocompleteField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { TriggerEventType } from './__generated__/TriggerLiveCreationKnowledgeMutation.graphql';

export const triggerMutationFieldPatch = graphql`
  mutation TriggerEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput!]!
  ) {
    triggerKnowledgeFieldPatch(id: $id, input: $input) {
      ...TriggerEditionOverview_trigger
    }
  }
`;

const triggerEditionOverviewFragment = graphql`
  fragment TriggerEditionOverview_trigger on Trigger {
    id
    name
    trigger_type
    event_types
    description
    filters
    created
    modified
    outcomes
    period
    trigger_time
    instance_trigger
    triggers {
      id
      name
    }
    resolved_instance_filters {
        id
        valid
        value
    }
  }
`;

interface TriggerEditionOverviewProps {
  data: TriggerEditionOverview_trigger$key;
  handleClose: () => void;
  paginationOptions?: TriggersLinesPaginationQuery$variables;
}

interface TriggerEditionFormValues {
  name: string;
  description: string | null;
  event_types: {
    value: TriggerEventType,
    label: string,
  }[];
  outcomes: {
    value: string,
    label: string,
  }[];
  trigger_ids: { value: string }[];
  period: string;
}

const TriggerEditionOverview: FunctionComponent<
TriggerEditionOverviewProps
> = ({ data, handleClose, paginationOptions }) => {
  const { t } = useFormatter();
  const trigger = useFragment(triggerEditionOverviewFragment, data);
  const filters = JSON.parse(trigger.filters ?? '{}');
  const [commitFieldPatch] = useMutation(triggerMutationFieldPatch);
  const [instanceFilters, setInstanceFilters] = useState({});
  const handleAddFilter = (
    key: string,
    id: string,
    value: Record<string, unknown> | string,
  ) => {
    if (filters[key] && filters[key].length > 0) {
      const updatedFilters = R.assoc(
        key,
        isUniqFilter(key)
          ? [{ id, value }]
          : R.uniqBy(R.prop('id'), [{ id, value }, ...filters[key]]),
        filters,
      );
      commitFieldPatch({
        variables: {
          id: trigger.id,
          input: { key: 'filters', value: JSON.stringify(updatedFilters) },
        },
      });
    } else {
      const updatedFilters = R.assoc(key, [{ id, value }], filters);
      commitFieldPatch({
        variables: {
          id: trigger.id,
          input: { key: 'filters', value: JSON.stringify(updatedFilters) },
        },
      });
    }
  };
  const handleRemoveFilter = (key: string) => {
    const updatedFilters = R.dissoc(key, filters);
    commitFieldPatch({
      variables: {
        id: trigger.id,
        input: { key: 'filters', value: JSON.stringify(updatedFilters) },
      },
    });
  };
  const onSubmit: FormikConfig<TriggerEditionFormValues>['onSubmit'] = (
    values,
    { setSubmitting },
  ) => {
    commitFieldPatch({
      variables: {
        id: trigger.id,
        input: values,
      },
      onCompleted: () => {
        setSubmitting(false);
        handleClose();
      },
    });
  };
  const triggerValidation = () => Yup.object().shape({
    name: Yup.string().required(t('This field is required')),
    description: Yup.string().nullable(),
    event_types:
        trigger.trigger_type === 'live'
          ? Yup.array().min(1, t('Minimum one event type')).required(t('This field is required'))
          : Yup.array().nullable(),
    outcomes:
        trigger.trigger_type === 'digest'
          ? Yup.array().min(1, t('Minimum one outcome')).required(t('This field is required'))
          : Yup.array().nullable(),
    period:
        trigger.trigger_type === 'digest'
          ? Yup.string().required(t('This field is required'))
          : Yup.string().nullable(),
    day: Yup.string().nullable(),
    time: Yup.string().nullable(),
    trigger_ids:
        trigger.trigger_type === 'digest'
          ? Yup.array()
            .min(1, t('Minimum one trigger'))
            .required(t('This field is required'))
          : Yup.array().nullable(),
  });
  const handleSubmitTriggers = (name: string, value: { value: string }[]) => triggerValidation()
    .validateAt(name, { [name]: value })
    .then(() => {
      commitFieldPatch({
        variables: {
          id: trigger.id,
          input: { key: name, value: value?.map(({ value: v }) => v) ?? '' },
        },
      });
    })
    .catch(() => false);
  const handleSubmitDay = (_: string, value: string) => {
    const day = value && value.length > 0 ? value : '1';
    const currentTime = trigger.trigger_time?.split('-') ?? [
      `${parse(dayStartDate()).utc().format('HH:mm:00.000')}Z`,
    ];
    const newTime = currentTime.length > 1
      ? `${day}-${currentTime[1]}`
      : `${day}-${currentTime[0]}`;
    return commitFieldPatch({
      variables: {
        id: trigger.id,
        input: { key: 'trigger_time', value: newTime },
      },
    });
  };
  const handleSubmitTime = (_: string, value: string) => {
    const time = value && value.length > 0
      ? `${parse(value).utc().format('HH:mm:00.000')}Z`
      : `${parse(dayStartDate()).utc().format('HH:mm:00.000')}Z`;
    const currentTime = trigger.trigger_time?.split('-') ?? [
      `${parse(dayStartDate()).utc().format('HH:mm:00.000')}Z`,
    ];
    const newTime = currentTime.length > 1 && trigger.period !== 'hour'
      ? `${currentTime[0]}-${time}`
      : time;
    return commitFieldPatch({
      variables: {
        id: trigger.id,
        input: { key: 'trigger_time', value: newTime },
      },
    });
  };
  const handleClearTime = () => {
    return commitFieldPatch({
      variables: {
        id: trigger.id,
        input: { key: 'trigger_time', value: '' },
      },
    });
  };
  const handleRemoveDay = () => {
    const currentTime = trigger.trigger_time?.split('-') ?? [
      `${parse(dayStartDate()).utc().format('HH:mm:00.000')}Z`,
    ];
    const newTime = currentTime.length > 1 ? currentTime[1] : currentTime[0];
    return commitFieldPatch({
      variables: {
        id: trigger.id,
        input: { key: 'trigger_time', value: newTime },
      },
    });
  };
  const handleAddDay = () => {
    const currentTime = trigger.trigger_time?.split('-') ?? [
      `${parse(dayStartDate()).utc().format('HH:mm:00.000')}Z`,
    ];
    const newTime = currentTime.length > 1 ? currentTime.join('-') : `1-${currentTime[0]}`;
    return commitFieldPatch({
      variables: {
        id: trigger.id,
        input: { key: 'trigger_time', value: newTime },
      },
    });
  };
  const handleSubmitField = (
    name: string,
    value: Option | string | string[],
  ) => {
    return triggerValidation()
      .validateAt(name, { [name]: value })
      .then(() => {
        commitFieldPatch({
          variables: {
            id: trigger.id,
            input: { key: name, value: value || '' },
          },
          onCompleted: () => {
            if (name === 'period') {
              if (value === 'hour') {
                handleClearTime();
              } else if (value === 'day') {
                handleRemoveDay();
              } else {
                handleAddDay();
              }
            }
          },
        });
      })
      .catch(() => false);
  };
  const currentTime = trigger.trigger_time?.split('-') ?? [
    dayStartDate().toISOString(),
  ];
  const eventTypesOptionsMap: Record<string, string> = {
    create: t('Creation'),
    update: t('Modification'),
    delete: t('Deletion'),
  };
  const eventTypesOptions: { value: TriggerEventType, label: string }[] = [
    { value: 'create', label: t('Creation') },
    { value: 'update', label: t('Modification') },
    { value: 'delete', label: t('Deletion') },
  ];
  const instanceEventTypesOptions = [
    { value: 'update', label: t('Modification') },
    { value: 'delete', label: t('Deletion') },
  ];
  const outcomesOptions = [
    {
      value: 'f4ee7b33-006a-4b0d-b57d-411ad288653d',
      label: t('User interface'),
    },
    {
      value: '44fcf1f4-8e31-4b31-8dbc-cd6993e1b822',
      label: t('Email'),
    },
  ];
  const outcomesOptionsMap: Record<string, string> = {
    'f4ee7b33-006a-4b0d-b57d-411ad288653d': t('User interface'),
    '44fcf1f4-8e31-4b31-8dbc-cd6993e1b822': t('Email'),
  };
  const initialValues = {
    name: trigger.name,
    description: trigger.description,
    event_types: convertEventTypes(trigger, eventTypesOptionsMap),
    outcomes: convertOutcomes(trigger, outcomesOptionsMap),
    period: trigger.period,
    trigger_ids: convertTriggers(trigger),
    day: currentTime.length > 1 ? currentTime[0] : '1',
    time:
      currentTime.length > 1
        ? `2000-01-01T${currentTime[1]}`
        : `2000-01-01T${currentTime[0]}`,
  };
  return (
    <Formik
      enableReinitialize={true}
      initialValues={initialValues as never}
      validationSchema={triggerValidation()}
      onSubmit={onSubmit}
    >
      {({ values, setFieldValue }) => (
        <Form style={{ margin: '20px 0 20px 0' }}>
          <Field
            component={TextField}
            variant="standard"
            name="name"
            label={t('Name')}
            fullWidth={true}
            onSubmit={handleSubmitField}
          />
          <Field
            component={MarkdownField}
            name="description"
            label={t('Description')}
            fullWidth={true}
            multiline={true}
            rows="4"
            onSubmit={handleSubmitField}
            style={{ marginTop: 20 }}
          />
          {trigger.trigger_type === 'live' && (
            <Field
              component={AutocompleteField}
              name="event_types"
              style={fieldSpacingContainerStyle}
              multiple={true}
              textfieldprops={{
                variant: 'standard',
                label: t('Triggering on'),
              }}
              options={trigger.instance_trigger ? instanceEventTypesOptions : eventTypesOptions}
              onChange={(name: string, value: { value: string, label: string }[]) => handleSubmitField(name, value.map((n) => n.value))}
              renderOption={(
                props: React.HTMLAttributes<HTMLLIElement>,
                option: { value: TriggerEventType, label: string },
              ) => (
                <MenuItem value={option.value} {...props}>
                  <Checkbox checked={values.event_types.map((n) => n.value).includes(option.value)} />
                  <ListItemText primary={option.label} />
                </MenuItem>
              )}
            />
          )}
          {trigger.trigger_type === 'digest' && (
            <TriggersField
              name="trigger_ids"
              setFieldValue={setFieldValue}
              values={values.trigger_ids}
              style={fieldSpacingContainerStyle}
              onChange={handleSubmitTriggers}
              paginationOptions={paginationOptions}
            />
          )}
          {trigger.trigger_type === 'digest' && (
            <Field
              component={SelectField}
              variant="standard"
              name="period"
              label={t('Period')}
              fullWidth={true}
              containerstyle={fieldSpacingContainerStyle}
              onChange={handleSubmitField}
            >
              <MenuItem value="hour">{t('hour')}</MenuItem>
              <MenuItem value="day">{t('day')}</MenuItem>
              <MenuItem value="week">{t('week')}</MenuItem>
              <MenuItem value="month">{t('month')}</MenuItem>
            </Field>
          )}
          {trigger.trigger_type === 'digest' && values.period === 'week' && (
            <Field
              component={SelectField}
              variant="standard"
              name="day"
              label={t('Week day')}
              fullWidth={true}
              containerstyle={fieldSpacingContainerStyle}
              onChange={handleSubmitDay}
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
          {trigger.trigger_type === 'digest' && values.period === 'month' && (
            <Field
              component={SelectField}
              variant="standard"
              name="day"
              label={t('Month day')}
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
          {trigger.trigger_type === 'digest' && values.period !== 'hour' && (
            <Field
              component={TimePickerField}
              name="time"
              withMinutes={true}
              onSubmit={handleSubmitTime}
              TextFieldProps={{
                label: t('Time'),
                variant: 'standard',
                fullWidth: true,
                style: { marginTop: 20 },
              }}
            />
          )}
          <Field
            component={AutocompleteField}
            name="outcomes"
            style={fieldSpacingContainerStyle}
            multiple={true}
            textfieldprops={{
              variant: 'standard',
              label: t('Notification'),
            }}
            options={outcomesOptions}
            onChange={(name: string, value: { value: string, label: string }[]) => handleSubmitField(name, value.map((n) => n.value))}
            renderOption={(
              props: React.HTMLAttributes<HTMLLIElement>,
              option: { value: string, label: string },
            ) => (
              <MenuItem value={option.value} {...props}>
                <Checkbox
                  checked={values.outcomes.map((n) => n.value).includes(option.value)}
                />
                <ListItemText
                  primary={option.label}
                />
              </MenuItem>
            )}
          />
          {trigger.trigger_type === 'live'
            && <span>
              {trigger.instance_trigger
                ? (<div style={fieldSpacingContainerStyle}>
                  <FilterAutocomplete
                    filterKey={'elementId'}
                    searchContext={{ entityTypes: ['Stix-Core-Object'] }}
                    defaultHandleAddFilter={handleAddFilter}
                    inputValues={instanceFilters}
                    setInputValues={setInstanceFilters}
                    openOnFocus={true}
                  />
                </div>)
                : <div>
                  <div style={{ marginTop: 35 }}>
                    <Filters
                      variant="text"
                      availableFilterKeys={[
                        'entity_type',
                        'x_opencti_workflow_id',
                        'assigneeTo',
                        'objectContains',
                        'markedBy',
                        'labelledBy',
                        'creator',
                        'createdBy',
                        'priority',
                        'severity',
                        'x_opencti_score',
                        'x_opencti_detection',
                        'revoked',
                        'confidence',
                        'indicator_types',
                        'pattern_type',
                        'fromId',
                        'toId',
                        'fromTypes',
                        'toTypes',
                      ]}
                      handleAddFilter={handleAddFilter}
                      handleRemoveFilter={undefined}
                      handleSwitchFilter={undefined}
                      noDirectFilters={true}
                      disabled={undefined}
                      size={undefined}
                      fontSize={undefined}
                      availableEntityTypes={undefined}
                      availableRelationshipTypes={undefined}
                      allEntityTypes={undefined}
                      type={undefined}
                      availableRelationFilterTypes={undefined}
                    />
                  </div>
                  <div className="clearfix"/>
                </div>
              }
              <FilterIconButton
                filters={filters}
                handleRemoveFilter={handleRemoveFilter}
                classNameNumber={2}
                redirection
                resolvedInstanceFilters={trigger.resolved_instance_filters ?? []}
              />
            </span>
          }
        </Form>
      )}
    </Formik>
  );
};

export default TriggerEditionOverview;
