import React from 'react';
import { graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import Button from '@common/button/Button';
import * as Yup from 'yup';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { DraftCreationMutation, DraftCreationMutation$variables } from '@components/drafts/__generated__/DraftCreationMutation.graphql';
import Drawer, { DrawerControlledDialProps } from '@components/common/drawer/Drawer';
import AuthorizedMembersField, { AuthorizedMembersFieldValue } from '@components/common/form/AuthorizedMembersField';
import { DraftsLinesPaginationQuery$variables } from '@components/drafts/__generated__/DraftsLinesPaginationQuery.graphql';
import { FormikConfig } from 'formik/dist/types';
import CreateEntityControlledDial from '../../../components/CreateEntityControlledDial';
import { insertNode } from '../../../utils/store';
import { handleErrorInForm } from '../../../relay/environment';
import TextField from '../../../components/TextField';
import { useFormatter } from '../../../components/i18n';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import useAuth from '../../../utils/hooks/useAuth';

export const draftCreationMutation = graphql`
    mutation DraftCreationMutation($input: DraftWorkspaceAddInput!) {
        draftWorkspaceAdd(input: $input) {
            id
            name
            currentUserAccessRight
            authorizedMembers {
              id
              name
              entity_type
              access_right
              member_id
              groups_restriction {
                id
                name
              }
            }
            ...Drafts_node
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
  authorizedMembers?: AuthorizedMembersFieldValue;
}

const DraftCreationForm: React.FC<DraftFormProps> = ({ updater, onCompleted, onReset }) => {
  const { t_i18n } = useFormatter();
  const { me: owner, settings } = useAuth();
  const showAllMembersLine = !settings.platform_organization?.id;
  const [commitCreationMutation] = useApiMutation<DraftCreationMutation>(draftCreationMutation);
  const draftValidation = () => Yup.object().shape({
    name: Yup.string().trim().min(2, t_i18n('Name must be at least 2 characters')).required(t_i18n('This field is required')),
  });
  const onSubmit: FormikConfig<DraftAddInput>['onSubmit'] = (values, { setSubmitting, setErrors, resetForm }) => {
    const input: DraftCreationMutation$variables['input'] = {
      name: values.name,
      authorized_members: !values.authorizedMembers
        ? null
        : values.authorizedMembers
            .filter((v) => v.accessRight !== 'none')
            .map((member) => ({
              id: member.value,
              access_right: member.accessRight,
              groups_restriction_ids: member.groupsRestriction?.length > 0
                ? member.groupsRestriction.map((group) => group.value)
                : undefined,
            })),
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
        setSubmitting(false);
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
        <Form>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }} data-testid="draft-creation-form">
            <Field
              component={TextField}
              name="name"
              label={t_i18n('Name')}
              fullWidth
              data-testid="draft-creation-form-name-input"
            />
            <Field
              name="authorizedMembers"
              component={AuthorizedMembersField}
              owner={owner}
              showAllMembersLine={showAllMembersLine}
              canDeactivate
              addMeUserWithAdminRights
              enableAccesses
              applyAccesses
            />
          </div>
          <div style={{ marginTop: 20, textAlign: 'right' }}>
            <Button
              variant="secondary"
              onClick={handleReset}
              disabled={isSubmitting}
              style={{ marginLeft: 10 }}
            >
              {t_i18n('Cancel')}
            </Button>
            <Button
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
  const updater = (store: RecordSourceSelectorProxy) => insertNode(
    store,
    'Pagination_draftWorkspaces',
    paginationOptions,
    'draftWorkspaceAdd',
  );
  const CreateDraftControlledDial = (props: DrawerControlledDialProps) => (
    <CreateEntityControlledDial entityType="DraftWorkspace" {...props} />
  );
  return (
    <Drawer
      title={t_i18n('Create a Draft')}
      controlledDial={CreateDraftControlledDial}
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
