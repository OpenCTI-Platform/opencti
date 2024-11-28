import React, { FunctionComponent } from 'react';
import { useFormatter } from '../../../../components/i18n';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import TextField from '../../../../components/TextField';
import { Field, Form, Formik } from 'formik';
import MarkdownField from '../../../../components/fields/MarkdownField';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import * as Yup from 'yup';
import { ExclusionListEditionQuery } from '@components/settings/exclusion_lists/__generated__/ExclusionListEditionQuery.graphql';
import { ExclusionListEdition_edition$key } from '@components/settings/exclusion_lists/__generated__/ExclusionListEdition_edition.graphql';

const exclusionListMutationFieldPatch = graphql`
  mutation ExclusionListEditionFieldPatchMutation($id: ID!, $input: [EditInput!]!) {
    exclusionListFieldPatch(id: $id, input: $input) {
      ...ExclusionListsLine_node
      ...ExclusionListEdition_edition
    }
  }
`;

const exclusionListEditionFragment = graphql`
  fragment ExclusionListEdition_edition on ExclusionList {
    id
    name
    description
  }
`;

export const exclusionListEditionQuery = graphql`
  query ExclusionListEditionQuery($id: String!) {
    exclusionList(id: $id) {
      ...ExclusionListEdition_edition
    }
  }
`;

const exclusionListValidation = (t: (n: string) => string) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string().nullable(),
});

interface ExclusionListEditionComponentProps {
  queryRef: PreloadedQuery<ExclusionListEditionQuery>;
  onClose: () => void;
}

interface ExclusionListEditionValues {
  name: string;
  description?: string | null;
}

const ExclusionListEdition: FunctionComponent<ExclusionListEditionComponentProps> = ({
  queryRef,
  onClose,
}) => {
  const { t_i18n } = useFormatter();

  const { exclusionList } = usePreloadedQuery<ExclusionListEditionQuery>(exclusionListEditionQuery, queryRef);
  const data = useFragment<ExclusionListEdition_edition$key>(exclusionListEditionFragment, exclusionList);
  const [commitFieldPatch] = useApiMutation(exclusionListMutationFieldPatch);

  const initialValues: ExclusionListEditionValues = {
    name: data?.name ?? '',
    description: data?.description,
  };

  return (
    <div>
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={exclusionListValidation(t_i18n)}
        onSubmit={() => {
        }}
        onClose={onClose}
      >
        {({ values, setFieldValue, setSubmitting, setErrors, isSubmitting }) => (
          <Form>
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
              fullWidth={true}
              multiline={true}
              rows={2}
              style={{ marginTop: 20 }}
            />
          </Form>
        )}
      </Formik>
    </div>
  );
};

export default ExclusionListEdition;
