import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { FieldOption } from '../../../../utils/field';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { FintelDesignEditionOverview_fintelDesign$key } from './__generated__/FintelDesignEditionOverview_fintelDesign.graphql';

const fintelDesignEditionPatchMutation = graphql`
  mutation FintelDesignEditionOverviewFieldPatchMutation($id: ID!, $input: [EditInput!]) {
    fintelDesignFieldPatch(id: $id, input: $input) {
      ...FintelDesignEditionOverview_fintelDesign
      ...FintelDesign_fintelDesign
    }
  }
`;

const fintelDesignOverviewFragment = graphql`
  fragment FintelDesignEditionOverview_fintelDesign on FintelDesign {
    id
    name
    description
  }
`;

interface FintelDesignEditionOverviewProps {
  data: FintelDesignEditionOverview_fintelDesign$key;
  enableReferences?: boolean;
}

interface FintelDesignEditionFormValues {
  name: string;
  description: string | null;
  message?: string;
  references?: FieldOption[];
}

const FintelDesignEditionOverviewComponent: FunctionComponent<
FintelDesignEditionOverviewProps
> = ({ data }) => {
  const { t_i18n } = useFormatter();
  const fintelDesign = useFragment(fintelDesignOverviewFragment, data);
  const [commit] = useApiMutation(fintelDesignEditionPatchMutation);

  const fintelDesignValidation = () => Yup.object().shape({
    name: Yup.string().trim().min(2, t_i18n('Name must be at least 2 characters')),
    description: Yup.string().nullable(),
  });

  const handleSubmitField = (name: string, value: FieldOption | string) => {
    commit({
      variables: {
        id: fintelDesign.id,
        input: { key: name, value: value ?? '' },
      },
    });
  };
  const initialValues: FintelDesignEditionFormValues = {
    name: fintelDesign.name,
    description: fintelDesign.description ?? '',
  };
  return (
    <Formik
      enableReinitialize={true}
      initialValues={initialValues}
      validateOnChange={true}
      validateOnBlur={true}
      validationSchema={fintelDesignValidation}
      onSubmit={() => {}}
    >
      {() => (
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
            style={{ marginTop: 20 }}
            onSubmit={handleSubmitField}
          />
        </Form>
      )}
    </Formik>
  );
};

export default FintelDesignEditionOverviewComponent;
