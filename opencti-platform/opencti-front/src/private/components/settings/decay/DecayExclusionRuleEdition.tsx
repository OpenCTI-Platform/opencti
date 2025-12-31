import React from 'react';
import { graphql } from 'react-relay';
import { useFormatter } from 'src/components/i18n';
import Drawer from '@components/common/drawer/Drawer';
import { Field, Form, Formik, FormikConfig } from 'formik';
import * as Yup from 'yup';
import { DecayExclusionRules_node$data } from '@components/settings/decay/__generated__/DecayExclusionRules_node.graphql';
import Box from '@mui/material/Box';
import Alert from 'src/components/Alert';
import Filters from '@components/common/lists/Filters';
import FilterIconButton from 'src/components/FilterIconButton';
import useFiltersState from 'src/utils/filters/useFiltersState';
import { deserializeFilterGroupForFrontend, emptyFilterGroup, serializeFilterGroupForBackend } from 'src/utils/filters/filtersUtils';
import { FilterGroup } from 'src/utils/filters/filtersHelpers-types';
import Button from '@common/button/Button';
import { handleErrorInForm } from '../../../../relay/environment';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import MarkdownField from '../../../../components/fields/MarkdownField';
import TextField from '../../../../components/TextField';
import { enabledFilters } from './DecayExclusionRuleCreationForm';

export const decayExclusionRuleEditionFieldPatch = graphql`
  mutation DecayExclusionRuleEditionFieldPatchMutation($id: ID!, $input: [EditInput!]!) {
    decayExclusionRuleFieldPatch(id: $id, input: $input) {
      ...DecayExclusionRules_node
    }
  }
`;

type DecayExclusionRuleEditionProps = {
  data: DecayExclusionRules_node$data;
  isOpen: boolean;
  onClose: () => void;
};

type DecayExclusionRuleEditionFormData = {
  name: string;
  description: string | null;
  decay_exclusion_filters: FilterGroup | null;
};

const decayExclusionRuleEditionValidator = (t: (value: string) => string) => {
  return Yup.object().shape({
    name: Yup.string().trim().min(2).required(t('This field is required')),
    description: Yup.string().nullable(),
  });
};

const DecayExclusionRuleEdition = ({ data, isOpen, onClose }: DecayExclusionRuleEditionProps) => {
  const { t_i18n } = useFormatter();
  const [filters, filterHelpers] = useFiltersState(
    deserializeFilterGroupForFrontend(data.decay_exclusion_filters) ?? emptyFilterGroup,
    deserializeFilterGroupForFrontend(data.decay_exclusion_filters) ?? emptyFilterGroup,
  );

  const [commitFieldPatch] = useApiMutation(decayExclusionRuleEditionFieldPatch);

  const onSubmit: FormikConfig<DecayExclusionRuleEditionFormData>['onSubmit'] = (
    values,
    { setSubmitting, setErrors },
  ) => {
    setSubmitting(true);
    const input = Object.entries(values).map(([key, value]) => {
      if (key === 'decay_exclusion_filters') {
        const jsonFilters = serializeFilterGroupForBackend(filters);
        return { key, value: [jsonFilters] };
      }
      return { key, value };
    });

    commitFieldPatch({
      variables: {
        id: data.id,
        input,
      },
      onCompleted: () => {
        setSubmitting(false);
        onClose();
      },
      onError: (error: Error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
    });
  };

  const initialValues: DecayExclusionRuleEditionFormData = {
    name: data.name,
    description: data.description ?? null,
    decay_exclusion_filters: deserializeFilterGroupForFrontend(data.decay_exclusion_filters),
  };

  const handleClose = () => {
    onClose();
    filterHelpers.handleClearAllFilters();
  };

  return (
    <Drawer
      title={t_i18n('Update a decay exclusion rule')}
      open={isOpen}
      onClose={handleClose}
    >
      <>
        <Alert
          content={t_i18n('Be careful, please define some filter for your exclusion rule, otherwise, since no filters are set, any indicator will match the rule and will have an exclusion rule')}
          severity="warning"
          style={{ marginBottom: 20 }}
        />
        <Formik<DecayExclusionRuleEditionFormData>
          initialValues={initialValues}
          validationSchema={decayExclusionRuleEditionValidator(t_i18n)}
          onSubmit={onSubmit}
        >
          {({ submitForm, handleReset, isSubmitting }) => (
            <Form style={{ margin: '20px 0 20px 0' }}>
              <Field
                component={TextField}
                name="name"
                label={t_i18n('Name')}
                fullWidth={true}
              />
              <Field
                component={MarkdownField}
                name="description"
                label={t_i18n('Description')}
                fullWidth
                multiline
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
                  {t_i18n('Update')}
                </Button>
              </div>
            </Form>
          )}
        </Formik>
      </>
    </Drawer>
  );
};

export default DecayExclusionRuleEdition;
