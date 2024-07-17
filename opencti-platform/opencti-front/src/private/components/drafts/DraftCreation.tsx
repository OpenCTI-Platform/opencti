import React from 'react';
import { graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import Button from '@mui/material/Button';
import * as Yup from 'yup';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { DraftCreationMutation, DraftCreationMutation$variables } from '@components/drafts/__generated__/DraftCreationMutation.graphql';
import Drawer, { DrawerControlledDialProps, DrawerVariant } from '@components/common/drawer/Drawer';
import { DraftsLinesPaginationQuery$variables } from '@components/drafts/__generated__/DraftsLinesPaginationQuery.graphql';
import { FormikConfig } from 'formik/dist/types';
import CreateEntityControlledDial from '../../../components/CreateEntityControlledDial';
import useHelper from '../../../utils/hooks/useHelper';
import { insertNode } from '../../../utils/store';
import { handleErrorInForm } from '../../../relay/environment';
import TextField from '../../../components/TextField';
import { useFormatter } from '../../../components/i18n';
import useApiMutation from '../../../utils/hooks/useApiMutation';

const draftCreationMutation = graphql`
  mutation DraftCreationMutation($input: DraftWorkspaceAddInput!) {
    draftWorkspaceAdd(input: $input) {
      id
      name
      ...DraftLine_node
    }
  }
`;

interface DraftFormProps {
  updater: (
    store: RecordSourceSelectorProxy,
    key: string,
  ) => void;
  onReset?: () => void;
  onCompleted?: () => void;
}

interface DraftAddInput {
  name: string;
}

const DraftCreationForm: React.FC<DraftFormProps> = ({ updater, onCompleted, onReset }) => {
  const { t_i18n } = useFormatter();
  const [commitCreationMutation] = useApiMutation<DraftCreationMutation>(draftCreationMutation);
  const draftValidation = () => Yup.object().shape({
    name: Yup.string().trim().min(2, t_i18n('Name must be at least 2 characters')).required(t_i18n('This field is required')),
  });
  const onSubmit: FormikConfig<DraftAddInput>['onSubmit'] = (values, { setSubmitting, setErrors, resetForm }) => {
    const input: DraftCreationMutation$variables['input'] = {
      name: values.name,
    };
    commitCreationMutation({
      variables: {
        input,
      },
      updater: (store) => {
        if (updater) {
          updater(store, 'draftWorkspaceAdd');
        }
      },
      onError: (error) => {
        handleErrorInForm(error, setErrors);
        setErrors(error);
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        if (onCompleted) {
          onCompleted();
        }
      },
    });
  };

  return (
    <Formik<DraftAddInput>
      initialValues={{ name: '' }}
      validationSchema={draftValidation}
      onSubmit={onSubmit}
      onReset={onReset}
    >
      {({ submitForm, handleReset, isSubmitting }) => (
        <Form style={{ margin: '20px 0 20px 0' }}>
          <Field
            component={TextField}
            name="name"
            label={t_i18n('Name')}
            detectDuplicate={['Draft']}
            fullWidth
            askAi
          />
          <div style={{ marginTop: 20, textAlign: 'right' }}>
            <Button
              variant="contained"
              onClick={handleReset}
              disabled={isSubmitting}
              style={{ marginLeft: 10 }}
            >
              {t_i18n('Cancel')}
            </Button>
            <Button
              variant="contained"
              color="secondary"
              onClick={submitForm}
              disabled={isSubmitting}
              style={{ marginLeft: 10 }}
            >
              {t_i18n('Create')}
            </Button>
          </div>
        </Form>
      )}

    </Formik>
  );
};

const DraftCreation = ({ paginationOptions }: { paginationOptions: DraftsLinesPaginationQuery$variables }) => {
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const isDraftFeatureEnable = isFeatureEnable('DRAFT_COPY_ID');
  const updater = (store: RecordSourceSelectorProxy) => insertNode(
    store,
    'Pagination_draftWorkspaces',
    paginationOptions,
    'draftWorkspaceAdd',
  );
  const CreateDraftControlledDial = (props: DrawerControlledDialProps) => (
    <CreateEntityControlledDial entityType='DraftWorkspaces' {...props} />
  );
  return (
    <Drawer
      title={t_i18n('Create a Draft')}
      variant={isDraftFeatureEnable ? undefined : DrawerVariant.create}
      controlledDial={isDraftFeatureEnable ? CreateDraftControlledDial : undefined}
    >
      {({ onClose }) => (
        <DraftCreationForm
          updater={updater}
          onCompleted={onClose}
          onReset={onClose}
        />
      )}
    </Drawer>
  );
};

export default DraftCreation;
