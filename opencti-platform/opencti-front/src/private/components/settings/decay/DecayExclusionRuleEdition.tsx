import React from 'react';
import { graphql } from 'react-relay';
import { useFormatter } from 'src/components/i18n';
import Drawer from '@components/common/drawer/Drawer';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import ObservableTypesField from '@components/common/form/ObservableTypesField';
import { DecayExclusionRules_node$data } from '@components/settings/decay/__generated__/DecayExclusionRules_node.graphql';
import { handleError } from '../../../../relay/environment';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import MarkdownField from '../../../../components/fields/MarkdownField';
import TextField from '../../../../components/TextField';

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
  decay_exclusion_observable_types: string[];
};

const decayExclusionRuleEditionValidator = (t: (value: string) => string) => {
  return Yup.object().shape({
    name: Yup.string().trim().min(2).required(t('This field is required')),
    description: Yup.string().nullable(),
    decay_exclusion_observable_types: Yup.array().of(Yup.string()),
  });
};

const DecayExclusionRuleEdition = ({ data, isOpen, onClose }: DecayExclusionRuleEditionProps) => {
  const { t_i18n } = useFormatter();

  const [commitFieldPatch] = useApiMutation(decayExclusionRuleEditionFieldPatch);

  const handleSubmitField = (name: string, value: string | string[]) => {
    commitFieldPatch({
      variables: {
        id: data.id,
        input: { key: name, value: value ?? '' },
      },
      onError: (error: Error) => {
        handleError(error);
      },
    });
  };

  const initialValues: DecayExclusionRuleEditionFormData = {
    name: data.name,
    description: data.description ?? null,
    decay_exclusion_observable_types: [...data.decay_exclusion_observable_types],
  };

  return (
    <Drawer
      title={t_i18n('Update a decay exclusion rule')}
      open={isOpen}
      onClose={onClose}
    >
      <Formik<DecayExclusionRuleEditionFormData>
        initialValues={initialValues}
        validationSchema={decayExclusionRuleEditionValidator(t_i18n)}
        onSubmit={() => {}}
      >
        {() => (
          <Form>
            <Field
              component={TextField}
              name="name"
              label={t_i18n('Name')}
              fullWidth={true}
              onSubmit={handleSubmitField}
            />
            <Field
              component={MarkdownField}
              name="description"
              label={t_i18n('Description')}
              fullWidth
              multiline
              rows={2}
              onSubmit={handleSubmitField}
              style={{ marginTop: 20 }}
            />
            <ObservableTypesField
              name="decay_exclusion_observable_types"
              label={t_i18n('Apply on indicator observable types (none = ALL)')}
              multiple
              onChange={handleSubmitField}
              style={{ marginTop: 20 }}
            />
          </Form>
        )}
      </Formik>
    </Drawer>
  );
};

export default DecayExclusionRuleEdition;
