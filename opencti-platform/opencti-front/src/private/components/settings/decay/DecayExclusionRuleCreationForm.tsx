import React from 'react';
import { Field, Form, Formik, FormikConfig } from 'formik';
import { useFormatter } from 'src/components/i18n';
import * as Yup from 'yup';
import { fieldSpacingContainerStyle } from 'src/utils/field';
import Button from '@mui/material/Button';
import { graphql } from 'react-relay';
import ObservableTypesField from '@components/common/form/ObservableTypesField';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import TextField from '../../../../components/TextField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import SwitchField from '../../../../components/fields/SwitchField';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { handleErrorInForm } from '../../../../relay/environment';

const decayExclusionRuleCreationFormAddMutation = graphql`
  mutation DecayExclusionRuleCreationFormAddMutation($input: DecayExclusionRuleAddInput!) {
    decayExclusionRuleAdd(input: $input) {
      ...DecayExclusionRules_node
    }
  }
`;

type DecayExclusionRuleCreationFormProps = {
  updater: (store: RecordSourceSelectorProxy, rootField: string) => void,
  onReset: () => void;
  onCompleted: () => void;
};

type DecayExclusionRuleCreationFormData = {
  name: string;
  description: string;
  decay_exclusion_observable_types: string[];
  active: boolean;
};

const decayExclusionRuleCreationValidator = (t: (value: string) => string) => {
  return Yup.object().shape({
    name: Yup.string().trim().min(2).required(t('This field is required')),
    description: Yup.string().nullable(),
    decay_exclusion_observable_types: Yup.array().of(Yup.string()),
    active: Yup.boolean(),
  });
};

const DecayExclusionRuleCreationForm = ({ updater, onReset, onCompleted }: DecayExclusionRuleCreationFormProps) => {
  const { t_i18n } = useFormatter();
  const [commit] = useApiMutation(decayExclusionRuleCreationFormAddMutation);

  const onSubmit: FormikConfig<DecayExclusionRuleCreationFormData>['onSubmit'] = (
    values,
    { setSubmitting, resetForm, setErrors },
  ) => {
    const { name, description, decay_exclusion_observable_types, active } = values;
    const input = {
      name,
      description,
      decay_exclusion_observable_types,
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
    decay_exclusion_observable_types: [],
    active: false,
  };

  return (
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
            name='name'
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
          <ObservableTypesField
            name="decay_exclusion_observable_types"
            label={t_i18n('Apply on indicator observable types (none = ALL)')}
            multiple={true}
            style={{ marginTop: 20 }}
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
              variant="contained"
              onClick={handleReset}
              disabled={isSubmitting}
              style={{ marginLeft: 16 }}
            >
              {t_i18n('Cancel')}
            </Button>
            <Button
              variant="contained"
              color="secondary"
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
  );
};

export default DecayExclusionRuleCreationForm;
