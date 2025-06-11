import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { Stack } from '@mui/material';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { FieldOption } from '../../../../utils/field';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { FintelDesignEditionOverview_fintelDesign$key } from './__generated__/FintelDesignEditionOverview_fintelDesign.graphql';
import FintelDesignDeletion from './FintelDesignDeletion';

const fintelDesignEditionPatchMutation = graphql`
  mutation FintelDesignEditionOverviewFieldPatchMutation($id: ID!, $input: [EditInput!], $file: Upload) {
    fintelDesignFieldPatch(id: $id, input: $input, file: $file) {
      id
      name
    }
  }
`;

export const fintelDesignEditionOverviewFocus = graphql`
  mutation FintelDesignEditionOverviewFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    fintelDesignContextPatch(id: $id, input: $input) {
      id
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
  fintelDesignRef: FintelDesignEditionOverview_fintelDesign$key;
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
> = ({ fintelDesignRef }) => {
  const { t_i18n } = useFormatter();
  const fintelDesign = useFragment(fintelDesignOverviewFragment, fintelDesignRef);
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
          <Stack flexDirection="row" justifyContent="flex-end" gap={2}>
            <FintelDesignDeletion
              id={fintelDesign.id}
            />
          </Stack>
        </Form>
      )}
    </Formik>
  );
};

export default FintelDesignEditionOverviewComponent;
