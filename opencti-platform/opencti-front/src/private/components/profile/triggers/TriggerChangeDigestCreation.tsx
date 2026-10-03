import React, { FunctionComponent, Suspense } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import { FormikConfig } from 'formik/dist/types';
import * as Yup from 'yup';
import { Text } from '@filigran/design-system';
import { Box } from '@mui/material';
import Button from '@common/button/Button';
import FormButtonContainer from '../../../../components/common/form/FormButtonContainer';
import MarkdownField from '../../../../components/fields/markdownField/MarkdownField';
import SelectFieldFds, { SelectItem } from '../../../../components/fields/SelectFieldFds';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import TimePickerField from '../../../../components/TimePickerField';
import FilterIconButton from '../../../../components/FilterIconButton';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { handleErrorInForm } from '../../../../relay/environment';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import { serializeFilterGroupForBackend, useAvailableFilterKeysForEntityTypes } from '../../../../utils/filters/filtersUtils';
import useFiltersState from '../../../../utils/filters/useFiltersState';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { insertNode } from '../../../../utils/store';
import { dayStartDate, parse } from '../../../../utils/Time';
import Drawer from '../../common/drawer/Drawer';
import NotifierField from '../../common/form/NotifierField';
import Filters from '../../common/lists/Filters';
import { hasPayloadErrors } from '../../common/time_machine/timeMachineMutations';
import { TriggersLinesPaginationQuery$variables } from './__generated__/TriggersLinesPaginationQuery.graphql';
import { TriggerChangeDigestCreationSavedFiltersQuery } from './__generated__/TriggerChangeDigestCreationSavedFiltersQuery.graphql';

const triggerChangeDigestCreationMutation = graphql`
  mutation TriggerChangeDigestCreationMutation($input: TriggerChangeDigestAddInput!) {
    triggerKnowledgeChangeDigestAdd(input: $input) {
      ...TriggerLine_node
    }
  }
`;

const triggerChangeDigestCreationSavedFiltersQuery = graphql`
  query TriggerChangeDigestCreationSavedFiltersQuery {
    savedFilters(first: 500, orderBy: name, orderMode: asc) {
      edges {
        node {
          id
          name
          filters
        }
      }
    }
  }
`;

const NO_SAVED_FILTER = 'none';
export const CHANGE_DIGEST_ENTITY_TYPES = [
  'Stix-Domain-Object',
  'Intrusion-Set',
  'Threat-Actor-Group',
  'Threat-Actor-Individual',
  'Campaign',
  'Malware',
  'Tool',
  'Attack-Pattern',
  'Vulnerability',
  'Incident',
  'Report',
];

interface TriggerChangeDigestFormValues {
  name: string;
  description: string;
  scope_entity_type: string;
  saved_filter: string;
  saved_filter_filters: string | null;
  period: string;
  day: string;
  time: string;
  notifiers: FieldOption[];
}

const changeDigestValidation = (t: (message: string) => string) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string().nullable(),
  scope_entity_type: Yup.string().required(t('This field is required')),
  period: Yup.string().required(t('This field is required')),
  notifiers: Yup.array().min(1, t('Minimum one notifier')).required(t('This field is required')),
  day: Yup.string().nullable(),
  time: Yup.string().nullable(),
});

const SavedFilterField = ({ onSelect }: { onSelect: (filters: string | null) => void }) => {
  const { t_i18n } = useFormatter();
  const data = useLazyLoadQuery<TriggerChangeDigestCreationSavedFiltersQuery>(triggerChangeDigestCreationSavedFiltersQuery, {}, { fetchPolicy: 'store-and-network' });
  const savedFilters = (data.savedFilters?.edges ?? []).map((edge) => edge?.node).filter((node) => !!node);
  return (
    <Field
      component={SelectFieldFds}
      variant="outlined"
      name="saved_filter"
      label={t_i18n('Saved filter')}
      fullWidth={true}
      containerstyle={fieldSpacingContainerStyle}
      onChange={(_: string, value: string) => onSelect(savedFilters.find((savedFilter) => savedFilter.id === value)?.filters ?? null)}
    >
      <SelectItem value={NO_SAVED_FILTER}>{t_i18n('No saved filter (use the filters below)')}</SelectItem>
      {savedFilters.map((savedFilter) => (
        <SelectItem key={savedFilter.id} value={savedFilter.id}>{savedFilter.name}</SelectItem>
      ))}
    </Field>
  );
};

interface TriggerChangeDigestCreationProps {
  open?: boolean;
  handleClose?: () => void;
  paginationOptions?: TriggersLinesPaginationQuery$variables;
}

/**
 * Creation of a change digest: at each period, the recipients receive the landscape changes
 * of a filter set (new relationships, removals, revocations, confidence and score changes).
 */
const TriggerChangeDigestCreation: FunctionComponent<TriggerChangeDigestCreationProps> = ({ open, handleClose, paginationOptions }) => {
  const { t_i18n } = useFormatter();
  const [commit] = useApiMutation(triggerChangeDigestCreationMutation);
  const [filters, helpers] = useFiltersState();
  const availableFilterKeys = useAvailableFilterKeysForEntityTypes(['Stix-Domain-Object']);
  const initialValues: TriggerChangeDigestFormValues = {
    name: '',
    description: '',
    scope_entity_type: 'Intrusion-Set',
    saved_filter: NO_SAVED_FILTER,
    saved_filter_filters: null,
    period: 'week',
    day: '1',
    time: dayStartDate().toISOString(),
    notifiers: [],
  };
  const onSubmit: FormikConfig<TriggerChangeDigestFormValues>['onSubmit'] = (values, { setSubmitting, setErrors, resetForm }) => {
    let triggerTime = `${parse(values.time).utc().format('HH:mm:00.000')}Z`;
    if (values.period !== 'hour' && values.period !== 'day') {
      const day = values.day && values.day.length > 0 ? values.day : '1';
      triggerTime = `${day}-${triggerTime}`;
    }
    // A saved filter is copied in the digest, so its recipients do not need access to the saved filter
    const hasFilters = filters.filters.length + filters.filterGroups.length > 0;
    let finalFilters: string | null = null;
    if (values.saved_filter !== NO_SAVED_FILTER && values.saved_filter_filters) {
      finalFilters = values.saved_filter_filters;
    } else if (hasFilters) {
      finalFilters = serializeFilterGroupForBackend(filters);
    }
    commit({
      variables: {
        input: {
          name: values.name,
          description: values.description,
          filters: finalFilters,
          scope_entity_types: [values.scope_entity_type],
          period: values.period,
          trigger_time: triggerTime,
          notifiers: values.notifiers.map(({ value }) => value),
        },
      },
      updater: (store: Parameters<typeof insertNode>[0]) => {
        insertNode(store, 'Pagination_triggersKnowledge', paginationOptions, 'triggerKnowledgeChangeDigestAdd');
      },
      onError: (error: Error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
      onCompleted: (_, errors) => {
        setSubmitting(false);
        if (hasPayloadErrors(errors)) return;
        resetForm();
        helpers.handleClearAllFilters();
        handleClose?.();
      },
    });
  };
  return (
    <Drawer open={open} onClose={handleClose} title={t_i18n('Create a change digest')}>
      <Formik<TriggerChangeDigestFormValues>
        initialValues={initialValues}
        validationSchema={changeDigestValidation(t_i18n)}
        onSubmit={onSubmit}
        onReset={() => handleClose?.()}
      >
        {({ submitForm, handleReset, isSubmitting, setFieldValue, values }) => (
          <Form>
            <Text variant="content-compact" style={{ color: 'var(--text-default-secondary)', marginBottom: 8 }}>
              {t_i18n('At each period, the recipients receive what changed on the entities of the filter set: new relationships, removals, revocations, confidence and score changes.')}
            </Text>
            <Field component={TextField} variant="outlined" name="name" label={t_i18n('Name')} fullWidth={true} />
            <Field
              component={MarkdownField}
              name="description"
              label={t_i18n('Description')}
              fullWidth={true}
              multiline={true}
              rows="4"
              style={{ marginTop: 20 }}
            />
            <Field
              component={SelectFieldFds}
              variant="outlined"
              name="scope_entity_type"
              label={t_i18n('Entity types')}
              fullWidth={true}
              containerstyle={fieldSpacingContainerStyle}
            >
              {CHANGE_DIGEST_ENTITY_TYPES.map((type) => (
                <SelectItem key={type} value={type}>{t_i18n(`entity_${type}`)}</SelectItem>
              ))}
            </Field>
            <Suspense fallback={<Loader variant={LoaderVariant.inline} />}>
              <SavedFilterField onSelect={(savedFilterFilters) => setFieldValue('saved_filter_filters', savedFilterFilters)} />
            </Suspense>
            {values.saved_filter === NO_SAVED_FILTER && (
              <Box sx={{ marginTop: '20px' }}>
                <Filters availableFilterKeys={availableFilterKeys} helpers={helpers} searchContext={{ entityTypes: ['Stix-Domain-Object'] }} />
                <FilterIconButton filters={filters} helpers={helpers} redirection searchContext={{ entityTypes: ['Stix-Domain-Object'] }} entityTypes={['Stix-Domain-Object']} />
              </Box>
            )}
            <Field
              component={SelectFieldFds}
              variant="outlined"
              name="period"
              label={t_i18n('Period')}
              fullWidth={true}
              containerstyle={fieldSpacingContainerStyle}
            >
              <SelectItem value="hour">{t_i18n('hour')}</SelectItem>
              <SelectItem value="day">{t_i18n('day')}</SelectItem>
              <SelectItem value="week">{t_i18n('week')}</SelectItem>
              <SelectItem value="month">{t_i18n('month')}</SelectItem>
            </Field>
            {values.period === 'week' && (
              <Field component={SelectFieldFds} variant="outlined" name="day" label={t_i18n('Week day')} fullWidth={true} containerstyle={fieldSpacingContainerStyle}>
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
              <Field component={SelectFieldFds} variant="outlined" name="day" label={t_i18n('Month day')} fullWidth={true} containerstyle={fieldSpacingContainerStyle}>
                {Array.from(Array(31).keys()).map((idx) => (
                  <SelectItem key={idx} value={(idx + 1).toString()}>{(idx + 1).toString()}</SelectItem>
                ))}
              </Field>
            )}
            {values.period !== 'hour' && (
              <Field
                component={TimePickerField}
                name="time"
                withMinutes={true}
                textFieldProps={{ label: t_i18n('Time'), variant: 'outlined', fullWidth: true, style: { marginTop: 20 } }}
              />
            )}
            <NotifierField name="notifiers" onChange={setFieldValue} />
            <FormButtonContainer>
              <Button variant="secondary" onClick={handleReset} disabled={isSubmitting}>{t_i18n('Cancel')}</Button>
              <Button onClick={submitForm} disabled={isSubmitting}>{t_i18n('Create')}</Button>
            </FormButtonContainer>
          </Form>
        )}
      </Formik>
    </Drawer>
  );
};

export default TriggerChangeDigestCreation;
