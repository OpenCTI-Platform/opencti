import React, { FunctionComponent } from 'react';
import { Field, Form, Formik, FormikConfig } from 'formik';
import Button from '@mui/material/Button';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import Drawer, { DrawerVariant } from '@components/common/drawer/Drawer';
import { disseminationListValidator, formatEmailsForApi } from '@components/settings/dissemination_lists/DisseminationListUtils';
import { graphql } from 'react-relay';
import { DisseminationListsLinesPaginationQuery$variables } from '@components/settings/dissemination_lists/__generated__/DisseminationListsLinesPaginationQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { insertNode } from '../../../../utils/store';
import { handleErrorInForm, MESSAGING$ } from '../../../../relay/environment';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { parseEmailList } from '../../../../utils/email';

const disseminationListCreationMutation = graphql`
    mutation DisseminationListCreationAddMutation($input: DisseminationListAddInput!) {
        disseminationListAdd(input: $input) {
            ...DisseminationListsLine_node
        }
    }
`;

interface DisseminationListCreationFormData {
  name: string;
  emails: string;
  description: string;
}

interface DisseminationListCreationFormProps {
  updater: (store: RecordSourceSelectorProxy, rootField: string) => void;
  onReset?: () => void;
  onCompleted?: () => void;
}

const DisseminationListCreationForm: FunctionComponent<DisseminationListCreationFormProps> = ({
  updater,
  onReset,
  onCompleted,
}) => {
  const { t_i18n } = useFormatter();
  const [commit] = useApiMutation(disseminationListCreationMutation);

  const onSubmit: FormikConfig<DisseminationListCreationFormData>['onSubmit'] = (
    values,
    { setSubmitting, resetForm, setErrors },
  ) => {
    const input = {
      name: values.name,
      emails: formatEmailsForApi(values.emails),
      description: values.description,
    };
    commit({
      variables: {
        input,
      },
      updater: (store) => {
        if (updater) {
          updater(store, 'disseminationListAdd');
        }
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        if (onCompleted) {
          onCompleted();
        }
      },
      onError: (error: Error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
    });
  };

  const initialValues: DisseminationListCreationFormData = {
    name: '',
    emails: '',
    description: '',
  };

  return (
    <Formik<DisseminationListCreationFormData>
      initialValues={initialValues}
      validateOnBlur={false}
      validateOnChange={false}
      validationSchema={disseminationListValidator(t_i18n)}
      onSubmit={onSubmit}
      onReset={onReset}
    >
      {({ submitForm, handleReset, isSubmitting }) => (
        <>
          <Field
            component={TextField}
            name="name"
            label={t_i18n('Name')}
            fullWidth={true}
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
          <Field
            component={TextField}
            name="emails"
            label={t_i18n('Emails (1 / line)')}
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
        </>
      )}
    </Formik>
  );
};

interface DisseminationListCreationProps {
  paginationOptions: DisseminationListsLinesPaginationQuery$variables;
}

const DisseminationListCreation: FunctionComponent<DisseminationListCreationProps> = ({
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();
  const updater = (store: RecordSourceSelectorProxy, rootField: string) => {
    insertNode(
      store,
      'Pagination_disseminationLists',
      paginationOptions,
      rootField,
    );
  };

  return (
    <Drawer
      title={t_i18n('Create a dissemination list')}
      variant={DrawerVariant.createWithPanel}
    >
      {({ onClose }) => (
        <>
          <DisseminationListCreationForm
            updater={updater}
            onCompleted={onClose}
            onReset={onClose}
          />
        </>
      )}
    </Drawer>
  );
};

export default DisseminationListCreation;
