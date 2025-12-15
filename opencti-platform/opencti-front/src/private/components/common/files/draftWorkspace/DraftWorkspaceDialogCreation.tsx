import React, { FunctionComponent } from 'react';
import { Field, Form, Formik } from 'formik';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@common/button/Button';
import { graphql } from 'react-relay';
import * as Yup from 'yup';
import { FormikConfig } from 'formik/dist/types';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { DraftsLinesPaginationQuery$variables } from '@components/drafts/__generated__/DraftsLinesPaginationQuery.graphql';
import AuthorizedMembersField, { AuthorizedMembersFieldValue } from '@components/common/form/AuthorizedMembersField';
import { useFormatter } from '../../../../../components/i18n';
import TextField from '../../../../../components/TextField';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { handleErrorInForm } from '../../../../../relay/environment';
import { insertNode } from '../../../../../utils/store';
import { DraftWorkspaceDialogCreationMutation, DraftWorkspaceDialogCreationMutation$variables } from './__generated__/DraftWorkspaceDialogCreationMutation.graphql';
import useAuth from '../../../../../utils/hooks/useAuth';
import { fieldSpacingContainerStyle } from '../../../../../utils/field';

const draftWorkspaceDialogCreationMutation = graphql`
  mutation DraftWorkspaceDialogCreationMutation($input: DraftWorkspaceAddInput!) {
    draftWorkspaceAdd(input: $input) {
      id
      name
      ...Drafts_node
    }
  }
`;

interface DraftWorkspaceCreationProps {
  openCreate?: boolean;
  handleCloseCreate?: () => void;
  entityId?: string;
  paginationOptions: DraftsLinesPaginationQuery$variables;
}

interface DraftAddInput {
  name: string;
  authorizedMembers?: AuthorizedMembersFieldValue;
}

const DraftWorkspaceDialogCreation: FunctionComponent<DraftWorkspaceCreationProps> = ({
  openCreate,
  handleCloseCreate,
  entityId,
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();
  const { me: owner, settings } = useAuth();
  const showAllMembersLine = !settings.platform_organization?.id;
  const [commit] = useApiMutation<DraftWorkspaceDialogCreationMutation>(
    draftWorkspaceDialogCreationMutation,
    undefined,
  );

  const updater = (store: RecordSourceSelectorProxy) => insertNode(
    store,
    'Pagination_draftWorkspaces',
    paginationOptions,
    'draftWorkspaceAdd',
  );

  const draftValidation = Yup.object().shape({
    name: Yup.string().trim().required(t_i18n('This field is required')),
  });

  const onSubmit: FormikConfig<DraftAddInput>['onSubmit'] = (values, { setSubmitting, setErrors, resetForm }) => {
    const input: DraftWorkspaceDialogCreationMutation$variables['input'] = {
      name: values.name,
      entity_id: entityId,
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
    commit({
      variables: {
        input,
      },
      updater: (store) => {
        updater(store);
      },
      onError: (error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
      },
    });
  };

  return (
    <Formik<DraftAddInput>
      enableReinitialize={true}
      initialValues={{ name: '' }}
      validationSchema={draftValidation}
      onSubmit={onSubmit}
      onReset={handleCloseCreate}
    >
      {({ submitForm, handleReset, isSubmitting }) => (
        <Form>
          <Dialog
            slotProps={{ paper: { elevation: 1 } }}
            open={!!openCreate}
            onClose={handleCloseCreate}
            fullWidth
          >
            <DialogTitle>{t_i18n('Create a Draft')}</DialogTitle>
            <DialogContent>
              <Field
                component={TextField}
                variant="standard"
                name="name"
                label={t_i18n('Name')}
                fullWidth
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
                style={fieldSpacingContainerStyle}
              />
            </DialogContent>
            <DialogActions>
              <Button variant="secondary" onClick={handleReset} disabled={isSubmitting}>
                {t_i18n('Cancel')}
              </Button>
              <Button
                type="submit"
                onClick={submitForm}
                disabled={isSubmitting}
              >
                {t_i18n('Create')}
              </Button>
            </DialogActions>
          </Dialog>
        </Form>
      )}
    </Formik>
  );
};

export default DraftWorkspaceDialogCreation;
