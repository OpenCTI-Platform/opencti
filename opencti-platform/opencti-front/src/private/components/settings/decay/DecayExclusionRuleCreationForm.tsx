import React from 'react';
import { Field, Form, Formik, FormikConfig } from 'formik';
import { useFormatter } from 'src/components/i18n';
import * as Yup from 'yup';
import { fieldSpacingContainerStyle } from 'src/utils/field';
import Button from '@common/button/Button';
import { graphql } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import useFiltersState from 'src/utils/filters/useFiltersState';
import Filters from '@components/common/lists/Filters';
import FilterIconButton from 'src/components/FilterIconButton';
import Box from '@mui/material/Box';
import TextField from '../../../../components/TextField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import SwitchField from '../../../../components/fields/SwitchField';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { handleErrorInForm } from '../../../../relay/environment';
import { emptyFilterGroup, serializeFilterGroupForBackend } from '../../../../utils/filters/filtersUtils';
import Alert from 'src/components/Alert';

const decayExclusionRuleCreationFormAddMutation = graphql`
  mutation DecayExclusionRuleCreationFormAddMutation($input: DecayExclusionRuleAddInput!) {
    decayExclusionRuleAdd(input: $input) {
      ...DecayExclusionRules_node
    }
  }
`;

type DecayExclusionRuleCreationFormProps = {
  updater: (store: RecordSourceSelectorProxy, rootField: string) => void;
  onReset: () => void;
  onCompleted: () => void;
};

type DecayExclusionRuleCreationFormData = {
  name: string;
  description: string;
  decay_exclusion_filters: string;
  active: boolean;
};

const decayExclusionRuleCreationValidator = (t: (value: string) => string) => {
  return Yup.object().shape({
    name: Yup.string().trim().min(2).required(t('This field is required')),
    description: Yup.string().nullable(),
    decay_exclusion_filters: Yup.array().of(Yup.string()),
    active: Yup.boolean(),
  });
};

export const enabledFilters = ['creator_id', 'createdBy', 'objectMarking', 'objectLabel', 'pattern_type', 'indicator_types', 'x_opencti_main_observable_type'];

const DecayExclusionRuleCreationForm = ({ updater, onReset, onCompleted }: DecayExclusionRuleCreationFormProps) => {
  const { t_i18n } = useFormatter();
  const [commit] = useApiMutation(decayExclusionRuleCreationFormAddMutation);
  const [filters, filterHelpers] = useFiltersState(emptyFilterGroup);
  const onSubmit: FormikConfig<DecayExclusionRuleCreationFormData>['onSubmit'] = (
    values,
    { setSubmitting, resetForm, setErrors },
  ) => {
    const { name, description, active } = values;
    const jsonFilters = serializeFilterGroupForBackend(filters);
    const input = {
      name,
      description,
      decay_exclusion_filters: jsonFilters,
      active,
    };

    commit({
      variables: { input },
      updater: (store) => {
        if (updater) {
          updater(store, 'decayExclusionRuleAdd');
        }
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        if (onCompleted) onCompleted();
      },
      onError: (error: Error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
    });
  };

  const initialValues: DecayExclusionRuleCreationFormData = {
    name: '',
    description: '',
    decay_exclusion_filters: '',
    active: false,
  };

  return (
    <>
      <Alert
        content={t_i18n('Be careful, please define some filter for your exclusion rule, otherwise, since no filters are set, any indicator will match the rule and will have an exclusion rule')}
        severity="warning"
        style={{ marginBottom: 20 }}
      />
      <Formik<DecayExclusionRuleCreationFormData>
        initialValues={initialValues}
        validateOnBlur={true}
        validateOnChange={true}
        validationSchema={decayExclusionRuleCreationValidator(t_i18n)}
        onSubmit={onSubmit}
        onReset={onReset}
      >
        {({ submitForm, handleReset, isSubmitting }) => (
          <Form style={{ margin: '20px 0 20px 0' }}>
            <Field
              component={TextField}
              name="name"
              label={t_i18n('Name')}
              fullWidth
              required
            />
            <Field
              component={MarkdownField}
              name="description"
              label={t_i18n('Description')}
              fullWidth={true}
              multiline={true}
              rows={2}
              style={{ marginTop: 20 }}
            />
            <Box sx={{
              paddingTop: '20px',
              display: 'flex',
              gap: 1,
            }}
            >
              <Filters
                availableFilterKeys={enabledFilters}
                helpers={filterHelpers}
                searchContext={{ entityTypes: ['Indicator'] }}
              />
            </Box>
            <FilterIconButton
              filters={filters}
              helpers={filterHelpers}
              styleNumber={2}
              searchContext={{ entityTypes: ['Indicator'] }}
            />
            <Field
              component={SwitchField}
              type="checkbox"
              name="active"
              label={t_i18n('Active')}
              containerstyle={fieldSpacingContainerStyle}
            />
            <div style={{ marginTop: 20, textAlign: 'right' }}>
              <Button
                variant="secondary"
                onClick={handleReset}
                disabled={isSubmitting}
                style={{ marginLeft: 16 }}
              >
                {t_i18n('Cancel')}
              </Button>
              <Button
                onClick={submitForm}
                disabled={isSubmitting}
                style={{ marginLeft: 16 }}
              >
                {t_i18n('Create')}
              </Button>
            </div>
          </Form>
        )}
      </Formik>
    </>
  );
};

export default DecayExclusionRuleCreationForm;
