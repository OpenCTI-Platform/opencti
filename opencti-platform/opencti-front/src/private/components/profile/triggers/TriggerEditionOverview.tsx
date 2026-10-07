import { Field, Form, Formik } from 'formik';
import { FormikConfig } from 'formik/dist/types';
import React, { FunctionComponent, useEffect, useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import * as Yup from 'yup';
import { Text } from '@filigran/design-system';
import { Box } from '@mui/material';
import { instanceTriggerDescription } from '@components/profile/triggers/TriggerLiveCreation';
import ComboboxField, { asMultiValue } from '../../../../components/ComboboxField';
import FilterIconButton from '../../../../components/FilterIconButton';
import { useFormatter } from '../../../../components/i18n';
import MarkdownField from '../../../../components/fields/markdownField/MarkdownField';

import SelectFieldFds, { SelectItem } from '../../../../components/fields/SelectFieldFds';
import TextField from '../../../../components/TextField';
import TimePickerField from '../../../../components/TimePickerField';
import { convertEventTypes, convertNotifiers, convertTriggers, filterEventTypesOptions, instanceEventTypesOptions } from '../../../../utils/edition';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import {
  deserializeFilterGroupForFrontend,
  emptyFilterGroup,
  getDefaultFilterObject,
  isFilterGroupNotEmpty,
  serializeFilterGroupForBackend,
  stixFilters,
  useAvailableFilterKeysForEntityTypes,
  useFilterDefinition,
} from '../../../../utils/filters/filtersUtils';
import { dayStartDate, formatTimeForToday, parse } from '../../../../utils/Time';
import NotifierField from '../../common/form/NotifierField';
import Filters from '../../common/lists/Filters';
import { TriggerEditionOverview_trigger$key } from './__generated__/TriggerEditionOverview_trigger.graphql';
import { TriggerEventType } from './__generated__/TriggerLiveCreationKnowledgeMutation.graphql';
import { TriggersLinesPaginationQuery$variables } from './__generated__/TriggersLinesPaginationQuery.graphql';
import TriggersField from './TriggersField';
import { CHANGE_DIGEST_ENTITY_TYPES } from './TriggerChangeDigestCreation';
import useFiltersState from '../../../../utils/filters/useFiltersState';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { hasPayloadErrors } from '../../common/time_machine/timeMachineMutations';
import SwitchField from '../../../../components/fields/SwitchField';
import { useTheme } from '@mui/material/styles';

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
    scope_entity_types
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

// The entity types a change digest was created with from a saved filter, kept until one type is picked
const SCOPE_ENTITY_TYPES_KEPT = 'auto';

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
  scope_entity_type: string;
}

const TriggerEditionOverview: FunctionComponent<TriggerEditionOverviewProps> = ({ data, handleClose, paginationOptions }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
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
  const changeDigestFilterKeys = useAvailableFilterKeysForEntityTypes(['Stix-Domain-Object']);
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
      onCompleted: (_, errors) => {
        setSubmitting(false);
        if (hasPayloadErrors(errors)) return;
        handleClose();
      },
    });
  };

  // Regular digests and change digests share their scheduling fields
  const isPeriodicDigest = trigger.trigger_type === 'digest' || trigger.trigger_type === 'change_digest';
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
      isPeriodicDigest
        ? Yup.array()
            .min(1, t_i18n('Minimum one notifier'))
            .required(t_i18n('This field is required'))
        : Yup.array().nullable(),
    period:
      isPeriodicDigest
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
      value: { value: string; label: string }[] | boolean,
    ) => void,
  ) => {
    const newInstanceTriggerValue = !instanceTrigger;
    setFieldValue(
      'event_types',
      newInstanceTriggerValue ? instanceEventTypesOptions : eventTypesOptions,
    );

    helpers.handleClearAllFilters();
    instanceTriggerFiltersHelpers.handleClearAllFilters();
    // instance_trigger has to live in Formik too: enableReinitialize rebuilds the form from initialValues after
    // every commitFieldPatch, so a value kept only in local state is wiped on the next round-trip.
    setFieldValue('instance_trigger', newInstanceTriggerValue);
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

  // The scope of a change digest is stored with its entity types: one type of the creation form, or the types of
  // the list of the saved filter it was created from, kept until another type is picked
  const scopeEntityTypes = trigger.scope_entity_types ?? [];
  const initialScopeEntityType = scopeEntityTypes.length === 1 && CHANGE_DIGEST_ENTITY_TYPES.includes(scopeEntityTypes[0])
    ? scopeEntityTypes[0]
    : SCOPE_ENTITY_TYPES_KEPT;
  const handleSubmitScopeEntityType = (_: string, value: string) => {
    if (value === SCOPE_ENTITY_TYPES_KEPT) return;
    commitFieldPatch({
      variables: {
        id: trigger.id,
        input: { key: 'scope_entity_types', value: [value] },
      },
    });
  };

  const initialValues = {
    name: trigger.name,
    scope_entity_type: initialScopeEntityType,
    instance_trigger: trigger.instance_trigger ?? false,
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
          {trigger.trigger_type === 'live' && (
            <Field
              component={ComboboxField}
              name="event_types"
              style={fieldSpacingContainerStyle}
              multiple={true}
              label={t_i18n('Triggering on')}
              options={
                trigger.instance_trigger
                  ? instanceEventTypesOptions
                  : filterEventTypesOptions
              }
              onChange={asMultiValue<{ value: string; label: string }>((
                name,
                value,
              ) => handleSubmitField(
                name,
                value.map((n) => n.value),
              ))}
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
          {isPeriodicDigest && (
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
          )}
          {isPeriodicDigest && values.period === 'week' && (
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
          {isPeriodicDigest && values.period === 'month' && (
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
          {isPeriodicDigest && values.period !== 'hour' && (
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
            onChange={(name, options) => handleSubmitField(
              name,
              options.map(({ value }) => value),
            )
            }
          />
          {trigger.trigger_type !== 'change_digest' && (
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
          )}
          {trigger.trigger_type === 'change_digest' && (
            <Box sx={{ marginTop: '20px' }} data-testid="change-digest-scope">
              <Text variant="title-md" style={{ marginBottom: 8 }}>{t_i18n('Filter set of the change digest')}</Text>
              <Field
                component={SelectFieldFds}
                variant="outlined"
                name="scope_entity_type"
                label={t_i18n('Entity types')}
                helpertext={values.scope_entity_type === SCOPE_ENTITY_TYPES_KEPT
                  ? t_i18n('With "Entity types of the scope", the digest compares the entity types of the list of the saved filter.')
                  : t_i18n('Only the entities of this type are compared.')}
                fullWidth={true}
                containerstyle={fieldSpacingContainerStyle}
                onChange={handleSubmitScopeEntityType}
              >
                {initialScopeEntityType === SCOPE_ENTITY_TYPES_KEPT && (
                  <SelectItem value={SCOPE_ENTITY_TYPES_KEPT}>{t_i18n('Entity types of the scope')}</SelectItem>
                )}
                {CHANGE_DIGEST_ENTITY_TYPES.map((type) => (
                  <SelectItem key={type} value={type}>{t_i18n(`entity_${type}`)}</SelectItem>
                ))}
              </Field>
              <Box sx={{ marginTop: '20px', display: 'flex', alignItems: 'center', gap: theme.spacing(1), marginBottom: theme.spacing(1) }}>
                <Filters availableFilterKeys={changeDigestFilterKeys} helpers={helpers} searchContext={{ entityTypes: ['Stix-Domain-Object'] }} />
                {!isFilterGroupNotEmpty(filters) && (
                  <Text variant="content-compact" style={{ color: 'var(--text-default-secondary)' }}>{t_i18n('No filters')}</Text>
                )}
              </Box>
              <FilterIconButton filters={filters} helpers={helpers} redirection searchContext={{ entityTypes: ['Stix-Domain-Object'] }} entityTypes={['Stix-Domain-Object']} />
            </Box>
          )}
          {trigger.trigger_type === 'live' && (
            <span>
              <Box sx={{
                marginTop: '20px',
                display: 'flex',
                alignItems: 'center',
                gap: theme.spacing(1),
                marginBottom: theme.spacing(1),
              }}
              >
                {!instanceTrigger
                  && (
                    <Filters
                      availableFilterKeys={stixFilters}
                      helpers={helpers}
                      searchContext={{ entityTypes: ['Stix-Core-Object', 'stix-core-relationship', 'Stix-Filtering'] }}
                    />
                  )
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
                    />
                  ) : (
                    <FilterIconButton
                      filters={filters}
                      helpers={helpers}
                      redirection
                      searchContext={{ entityTypes: ['Stix-Core-Object', 'stix-core-relationship'] }}
                      entityTypes={['Stix-Core-Object', 'stix-core-relationship', 'Stix-Filtering']}
                    />
                  )
              }
            </span>
          )}
        </Form>
      )}
    </Formik>
  );
};

export default TriggerEditionOverview;
