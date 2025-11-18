import Checkbox from '@mui/material/Checkbox';
import ListItemText from '@mui/material/ListItemText';
import MenuItem from '@mui/material/MenuItem';
import { Field, Form, Formik } from 'formik';
import { FormikConfig } from 'formik/dist/types';
import React, { FunctionComponent, useEffect, useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import * as Yup from 'yup';
import { Box } from '@mui/material';
import { instanceTriggerDescription } from '@components/profile/triggers/TriggerLiveCreation';
import AutocompleteField from '../../../../components/AutocompleteField';
import FilterIconButton from '../../../../components/FilterIconButton';
import { useFormatter } from '../../../../components/i18n';
import MarkdownField from '../../../../components/fields/MarkdownField';
import SelectField from '../../../../components/fields/SelectField';
import TextField from '../../../../components/TextField';
import TimePickerField from '../../../../components/TimePickerField';
import { convertEventTypes, convertNotifiers, convertTriggers, filterEventTypesOptions, instanceEventTypesOptions } from '../../../../utils/edition';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import {
  deserializeFilterGroupForFrontend,
  emptyFilterGroup,
  getDefaultFilterObject,
  serializeFilterGroupForBackend,
  stixFilters,
  useFilterDefinition,
} from '../../../../utils/filters/filtersUtils';
import { dayStartDate, formatTimeForToday, parse } from '../../../../utils/Time';
import NotifierField from '../../common/form/NotifierField';
import Filters from '../../common/lists/Filters';
import { TriggerEditionOverview_trigger$key } from './__generated__/TriggerEditionOverview_trigger.graphql';
import { TriggerEventType } from './__generated__/TriggerLiveCreationKnowledgeMutation.graphql';
import { TriggersLinesPaginationQuery$variables } from './__generated__/TriggersLinesPaginationQuery.graphql';
import TriggersField from './TriggersField';
import useFiltersState from '../../../../utils/filters/useFiltersState';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import SwitchField from '../../../../components/fields/SwitchField';

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
    notifiers {
      id
      name
    }
    period
    trigger_time
    instance_trigger
    triggers {
      id
      name
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
    value: TriggerEventType;
    label: string;
  }[];
  notifiers: {
    value: string;
    label: string;
  }[];
  trigger_ids: { value: string }[];
  period: string;
}

const TriggerEditionOverview: FunctionComponent<TriggerEditionOverviewProps> = ({ data, handleClose, paginationOptions }) => {
  const { t_i18n } = useFormatter();
  const defaultInstanceTriggerFilters = {
    ...emptyFilterGroup,
    filters: [getDefaultFilterObject('connectedToId', useFilterDefinition('connectedToId', ['Instance']))],
  };
  const trigger = useFragment(triggerEditionOverviewFragment, data);
  const [commitFieldPatch] = useApiMutation(triggerMutationFieldPatch);
  const [filters, helpers] = useFiltersState(deserializeFilterGroupForFrontend(trigger.filters) ?? undefined);
  const [instanceTriggerFilters, instanceTriggerFiltersHelpers] = useFiltersState(deserializeFilterGroupForFrontend(trigger.filters)
      ?? defaultInstanceTriggerFilters, defaultInstanceTriggerFilters);
  const [instanceTrigger, setInstanceTrigger] = useState<boolean>(trigger.instance_trigger ?? false);
  const eventTypesOptions: { value: TriggerEventType; label: string }[] = [
    { value: 'create', label: t_i18n('Creation') },
    { value: 'update', label: t_i18n('Modification') },
    { value: 'delete', label: t_i18n('Deletion') },
  ];

  useEffect(() => {
    commitFieldPatch({
      variables: {
        id: trigger.id,
        input: {
          key: 'filters',
          value: instanceTrigger ? serializeFilterGroupForBackend(instanceTriggerFilters) : serializeFilterGroupForBackend(filters),
        },
      },
    });
  }, [filters, instanceTriggerFilters]);

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
    name: Yup.string().required(t_i18n('This field is required')),
    description: Yup.string().nullable(),
    event_types:
      trigger.trigger_type === 'live'
        ? Yup.array()
          .min(1, t_i18n('Minimum one event type'))
          .required(t_i18n('This field is required'))
        : Yup.array().nullable(),
    notifiers:
      trigger.trigger_type === 'digest'
        ? Yup.array()
          .min(1, t_i18n('Minimum one notifier'))
          .required(t_i18n('This field is required'))
        : Yup.array().nullable(),
    period:
      trigger.trigger_type === 'digest'
        ? Yup.string().required(t_i18n('This field is required'))
        : Yup.string().nullable(),
    day: Yup.string().nullable(),
    time: Yup.string().nullable(),
    trigger_ids:
      trigger.trigger_type === 'digest'
        ? Yup.array()
          .min(1, t_i18n('Minimum one trigger'))
          .required(t_i18n('This field is required'))
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
    value: FieldOption | string | string[],
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

  const onChangeInstanceTrigger = (
    setFieldValue: (
      key: string,
      value: { value: string; label: string }[],
    ) => void,
  ) => {
    const newInstanceTriggerValue = !instanceTrigger;
    setFieldValue(
      'event_types',
      newInstanceTriggerValue ? instanceEventTypesOptions : eventTypesOptions,
    );

    helpers.handleClearAllFilters();
    instanceTriggerFiltersHelpers.handleClearAllFilters();
    setInstanceTrigger(newInstanceTriggerValue);

    commitFieldPatch({
      variables: {
        id: trigger.id,
        input: {
          key: 'instance_trigger',
          value: newInstanceTriggerValue,
        },
      },
    });
  };

  const currentTime = trigger.trigger_time?.split('-') ?? [
    dayStartDate().toISOString(),
  ];

  const initialValues = {
    name: trigger.name,
    description: trigger.description,
    event_types: convertEventTypes(trigger),
    notifiers: convertNotifiers(trigger),
    trigger_ids: convertTriggers(trigger),
    period: trigger.period,
    day: currentTime.length > 1 ? currentTime[0] : '1',
    time:
      currentTime.length > 1
        ? formatTimeForToday(currentTime[1])
        : formatTimeForToday(currentTime[0]),
  };
  return (
    <Formik
      enableReinitialize={true}
      initialValues={initialValues as never}
      validationSchema={triggerValidation()}
      onSubmit={onSubmit}
    >
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
          {trigger.trigger_type === 'live' && (
            <Field
              component={AutocompleteField}
              name="event_types"
              style={fieldSpacingContainerStyle}
              multiple={true}
              textfieldprops={{
                variant: 'standard',
                label: t_i18n('Triggering on'),
              }}
              options={
                trigger.instance_trigger
                  ? instanceEventTypesOptions
                  : filterEventTypesOptions
              }
              onChange={(
                name: string,
                value: { value: string; label: string }[],
              ) => handleSubmitField(
                name,
                value.map((n) => n.value),
              )
              }
              renderOption={(
                props: React.HTMLAttributes<HTMLLIElement>,
                option: { value: TriggerEventType; label: string },
              ) => (
                <MenuItem value={option.value} {...props}>
                  <Checkbox
                    checked={values.event_types
                      .map((n) => n.value)
                      .includes(option.value)}
                  />
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
          )}
          {trigger.trigger_type === 'digest' && values.period === 'week' && (
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
          {trigger.trigger_type === 'digest' && values.period === 'month' && (
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
          {trigger.trigger_type === 'digest' && values.period !== 'hour' && (
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
            onChange={(name, options) => handleSubmitField(
              name,
              options.map(({ value }) => value),
            )
            }
          />
          <Field
            component={SwitchField}
            type="checkbox"
            name="instance_trigger"
            label={t_i18n('Subscription to specific object(s)')}
            tooltip={instanceTriggerDescription}
            containerstyle={{ marginTop: 20 }}
            onChange={() => onChangeInstanceTrigger(setFieldValue)}
            checked={instanceTrigger}
          />
          {trigger.trigger_type === 'live' && (
            <span>
              <Box sx={{
                marginTop: '20px',
                display: 'flex',
                gap: 1,
              }}
              >
                {!instanceTrigger
                  && <Filters
                    availableFilterKeys={stixFilters}
                    helpers={helpers}
                    searchContext={{ entityTypes: ['Stix-Core-Object', 'stix-core-relationship', 'Stix-Filtering'] }}
                     />
                }
              </Box>

              {instanceTrigger
                ? (
                  <FilterIconButton
                    filters={instanceTriggerFilters}
                    helpers={{
                      ...instanceTriggerFiltersHelpers,
                      handleSwitchLocalMode: () => undefined, // connectedToId filter can only have the 'or' local mode
                    }}
                    redirection
                    entityTypes={['Instance']}
                    filtersRestrictions={{ preventLocalModeSwitchingFor: ['connectedToId'], preventRemoveFor: ['connectedToId'] }}
                    styleNumber={2}
                  />
                ) : (
                  <FilterIconButton
                    filters={filters}
                    helpers={helpers}
                    redirection
                    searchContext={{ entityTypes: ['Stix-Core-Object', 'stix-core-relationship'] }}
                    entityTypes={['Stix-Core-Object', 'stix-core-relationship', 'Stix-Filtering']}
                    styleNumber={2}
                  />)
              }
            </span>
          )}
        </Form>
      )}
    </Formik>
  );
};

export default TriggerEditionOverview;
