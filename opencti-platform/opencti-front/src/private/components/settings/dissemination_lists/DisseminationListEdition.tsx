import React, { FunctionComponent } from 'react';
import { graphql } from 'react-relay';
import Drawer from '@components/common/drawer/Drawer';
import { Field, Formik, FormikConfig } from 'formik';
import { DisseminationListsLine_node$data } from '@components/settings/dissemination_lists/__generated__/DisseminationListsLine_node.graphql';
import { disseminationListValidator, formatEmailsForApi, formatEmailsForFront } from '@components/settings/dissemination_lists/DisseminationListUtils';
import { useTheme } from '@mui/styles';
import { handleErrorInForm, MESSAGING$ } from '../../../../relay/environment';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import TextField from '../../../../components/TextField';
import { useFormatter } from '../../../../components/i18n';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { parseEmailList } from '../../../../utils/email';
import type { Theme } from '../../../../components/Theme';

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
}

const DisseminationListEdition: FunctionComponent<DisseminationListEditionComponentProps> = ({
  data,
  isOpen,
  onClose,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const [commitFieldPatch] = useApiMutation(disseminationListMutationFieldPatch);

  const onSubmit: FormikConfig<DisseminationListEditionFormData>['onSubmit'] = (
    values,
    { setSubmitting, setErrors },
  ) => {
    setSubmitting(true);

    const input = Object.entries(values)
      .map(([key, value]) => {
        if (key === 'emails') {
          return { key, value: formatEmailsForApi(value) };
        }
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
    emails: formatEmailsForFront(data.emails),
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
        {({ submitForm }) => (
          <>
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
              style={{ marginTop: theme.spacing(2) }}
            />
            <Field
              component={TextField}
              controlledSelectedTab='write'
              name="emails"
              label={t_i18n('Emails (1 / line)')}
              onSubmit={submitForm}
              fullWidth={true}
              multiline={true}
              rows={20}
              style={{ marginTop: theme.spacing(2) }}
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
          </>
        )}
      </Formik>
    </Drawer>
  );
};

export default DisseminationListEdition;
