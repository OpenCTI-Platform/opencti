import React, { FunctionComponent } from 'react';
import { graphql } from 'react-relay';
import Drawer from '@components/common/drawer/Drawer';
import { Field, Form, Formik, FormikConfig } from 'formik';
import Button from '@mui/material/Button';
import { DisseminationListsLine_node$data } from '@components/settings/dissemination_lists/__generated__/DisseminationListsLine_node.graphql';
import disseminationListValidator from '@components/settings/dissemination_lists/DisseminationListUtils';
import { handleErrorInForm, MESSAGING$ } from '../../../../relay/environment';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import TextField from '../../../../components/TextField';
import { useFormatter } from '../../../../components/i18n';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { parseEmailList } from '../../../../utils/email';

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
  description: string;
  dissemination_list_values_count?: number;
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
    if (values.emails) {
      values.dissemination_list_values_count = values.emails.split('\n').length;
    }

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
    description: data.description || '',
  };

  return (
    <Drawer
      title={t_i18n('Update a dissemination list')}
      open={isOpen}
      onClose={onClose}
    >
      <Formik<DisseminationListEditionFormData>
        enableReinitialize={true}
        validateOnBlur={true}
        validateOnChange={true}
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
              onSubmit={submitForm}
              fullWidth={true}
              required
            />
            <Field
              component={MarkdownField}
              name="description"
              label={t_i18n('Description')}
              onSubmit={submitForm}
              fullWidth={true}
              multiline={true}
              rows={2}
              style={{ marginTop: 20 }}
            />
            <Field
              component={TextField}
              controlledSelectedTab='write'
              name="emails"
              label={t_i18n('Emails')}
              onSubmit={submitForm}
              fullWidth={true}
              multiline={true}
              rows={20}
              style={{ marginTop: 20 }}
              required
              onBeforePaste={(pastedText: string) => {
                // on pasting data, we try to extract emails
                const extractedEmails = parseEmailList(pastedText);
                if (extractedEmails.length > 0) {
                  MESSAGING$.notifySuccess(t_i18n('', { id: '{count} email address(es) extracted from pasted text', values: { count: extractedEmails.length } }));
                  return extractedEmails.join('\n'); // alter the pasted content
                }
                return pastedText; // do not alter pasted content; it's probably invalid anyway
              }}
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
            </div>
          </Form>
        )}
      </Formik>
    </Drawer>
  );
};

export default DisseminationListEdition;
