import React, { FunctionComponent } from 'react';
import { graphql } from 'react-relay';
import Drawer from '@components/common/drawer/Drawer';
import { Field, Form, Formik, FormikConfig } from 'formik';
import Loader from 'src/components/Loader';
import Button from '@mui/material/Button';
import { DisseminationListsLine_node$data } from '@components/settings/dissemination_lists/__generated__/DisseminationListsLine_node.graphql';
import disseminationListValidator from '@components/settings/dissemination_lists/DisseminationListUtils';
import { handleErrorInForm } from '../../../../relay/environment';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import TextField from '../../../../components/TextField';
import { useFormatter } from '../../../../components/i18n';

export const disseminationListMutationFieldPatch = graphql`
    mutation DisseminationListEditionFieldPatchMutation($id: ID!, $input: [EditInput!]!) {
        disseminationListFieldPatch(id: $id, input: $input) {
            ...DisseminationListsLine_node
        }
    }
`;

interface DisseminationListEditionComponentProps {
  data: DisseminationListsLine_node$data;
  isOpen: boolean;
  onClose: () => void;
}

interface DisseminationListEditionFormData {
  name: string;
  emails: string;
}

const DisseminationListEdition: FunctionComponent<DisseminationListEditionComponentProps> = ({
  data,
  isOpen,
  onClose,
}) => {
  const { t_i18n } = useFormatter();

  const [commitFieldPatch] = useApiMutation(disseminationListMutationFieldPatch);

  const onSubmit: FormikConfig<DisseminationListEditionFormData>['onSubmit'] = (
    values,
    { setSubmitting, setErrors },
  ) => {
    setSubmitting(true);

    const input = Object.entries(values)
      .map(([key, value]) => {
        return {
          key,
          value,
        };
      });

    commitFieldPatch({
      variables: {
        id: data?.id,
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

  const initialValues: DisseminationListEditionFormData = {
    name: data.name,
    emails: data.emails,
  };

  return (
    <Drawer
      title={t_i18n('Update an dissemination list')}
      open={isOpen}
      onClose={onClose}
    >
      {initialValues
        ? (
          <Formik<DisseminationListEditionFormData>
            enableReinitialize={true}
            validateOnBlur={false}
            validateOnChange={false}
            initialValues={initialValues}
            validationSchema={disseminationListValidator(t_i18n)}
            onSubmit={onSubmit}
          >
            {({ submitForm, isSubmitting }) => (
              <Form style={{ margin: '20px 0 20px 0' }}>
                <Field
                  component={TextField}
                  name="name"
                  label={t_i18n('Name')}
                  fullWidth={true}
                  required
                />
                <Field
                  component={TextField}
                  controlledSelectedTab='write'
                  name="emails"
                  label={t_i18n('Emails')}
                  fullWidth={true}
                  multiline={true}
                  rows={4}
                  style={{ marginTop: 20 }}
                  required
                />
                <div style={{ marginTop: 20, textAlign: 'right' }}>
                  <Button
                    variant="contained"
                    disabled={isSubmitting}
                    style={{ marginLeft: 16 }}
                    onClick={onClose}
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
                    {t_i18n('Update')}
                  </Button>
                </div>
              </Form>
            )}
          </Formik>
        )
        : <Loader />
      }
    </Drawer>
  );
};

export default DisseminationListEdition;
