import React, { FunctionComponent, useState } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as R from 'ramda';
import * as Yup from 'yup';
import { useTheme } from '@mui/styles';
import { useNavigate } from 'react-router-dom';
import { Button, Dialog, DialogActions, DialogContent, DialogContentText } from '@mui/material';
import { SubscriptionFocus } from '../../../../components/Subscription';
import TextField from '../../../../components/TextField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { useFormatter } from '../../../../components/i18n';
import { RoleEditionOverview_role$data } from './__generated__/RoleEditionOverview_role.graphql';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import type { Theme } from '../../../../components/Theme';
import Transition from '../../../../components/Transition';
import useHelper from '../../../../utils/hooks/useHelper';

const roleMutationFieldPatch = graphql`
  mutation RoleEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
  ) {
    roleEdit(id: $id) {
      fieldPatch(input: $input) {
        ...RoleEditionOverview_role
      }
    }
  }
`;

const roleEditionOverviewFocus = graphql`
  mutation RoleEditionOverviewFocusMutation($id: ID!, $input: EditContext!) {
    roleEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

export const roleDeletionMutation = graphql`
  mutation RoleEditionOverviewDeletionMutation($id: ID!) {
    roleEdit(id: $id) {
      delete
    }
  }
`;

const roleValidation = (t: (n: string) => string) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string().nullable(),
});

interface RoleEditionOverviewComponentProps {
  role: RoleEditionOverview_role$data,
  context: ReadonlyArray<{
    readonly focusOn?: string | null;
    readonly name: string;
  }> | null | undefined,
}

const RoleEditionOverviewComponent: FunctionComponent<RoleEditionOverviewComponentProps> = ({ role, context }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const navigate = useNavigate();
  const [deleting, setDeleting] = useState(false);
  const [displayDelete, setDisplayDelete] = useState(false);

  const deleteSuccessMessage = t_i18n('', {
    id: '... successfully deleted',
    values: { entity_type: t_i18n('Role') },
  });
  const [commit] = useApiMutation(
    roleDeletionMutation,
    undefined,
    { successMessage: deleteSuccessMessage },
  );

  const handleOpenDelete = () => setDisplayDelete(true);
  const handleCloseDelete = () => setDisplayDelete(false);
  const submitDelete = (roleId: string) => {
    setDeleting(true);
    commit({
      variables: { id: roleId },
      onCompleted: () => {
        setDeleting(false);
        navigate('/dashboard/settings/accesses/roles');
      },
    });
  };

  const initialValues = R.pick(
    ['name', 'description'],
    role,
  );
  const [commitFocus] = useApiMutation(roleEditionOverviewFocus);
  const [commitFieldPatch] = useApiMutation(roleMutationFieldPatch);
  const handleChangeFocus = (name: string) => {
    commitFocus({
      variables: {
        id: role.id,
        input: {
          focusOn: name,
        },
      },
    });
  };
  const handleSubmitField = (name: string, value: string | boolean) => {
    roleValidation(t_i18n)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitFieldPatch({
          variables: { id: role.id, input: { key: name, value } },
        });
      })
      .catch(() => false);
  };
  return (
    <div>
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={roleValidation(t_i18n)}
        onSubmit={() => {}}
      >
        {() => (
          <Form style={{ marginTop: theme.spacing(2) }}>
            <Field
              component={TextField}
              variant="standard"
              name="name"
              label={t_i18n('Name')}
              fullWidth={true}
              onFocus={handleChangeFocus}
              onSubmit={handleSubmitField}
              helperText={
                <SubscriptionFocus context={context} fieldName="name" />
              }
            />
            <Field
              component={MarkdownField}
              name="description"
              label={t_i18n('Description')}
              fullWidth={true}
              multiline={true}
              rows={4}
              style={{ marginTop: 20 }}
              onFocus={handleChangeFocus}
              onSubmit={handleSubmitField}
              helperText={
                <SubscriptionFocus context={context} fieldName="description" />
              }
            />
            {isFABReplaced && (<>
              <Button
                onClick={handleOpenDelete}
                variant='contained'
                color='error'
                disabled={deleting}
                sx={{ marginTop: 2 }}
              >
                {t_i18n('Delete')}
              </Button>
              <Dialog
                open={displayDelete}
                PaperProps={{ elevation: 1 }}
                keepMounted={true}
                TransitionComponent={Transition}
                onClose={handleCloseDelete}
              >
                <DialogContent>
                  <DialogContentText>
                    {t_i18n('Do you want to delete this role?')}
                  </DialogContentText>
                </DialogContent>
                <DialogActions>
                  <Button
                    onClick={handleCloseDelete}
                    disabled={deleting}
                  >
                    {t_i18n('Cancel')}
                  </Button>
                  <Button
                    color="secondary"
                    onClick={() => submitDelete(role.id)}
                    disabled={deleting}
                  >
                    {t_i18n('Delete')}
                  </Button>
                </DialogActions>
              </Dialog>
            </>)}
          </Form>
        )}
      </Formik>
    </div>
  );
};

const RoleEditionOverview = createFragmentContainer(
  RoleEditionOverviewComponent,
  {
    role: graphql`
      fragment RoleEditionOverview_role on Role {
        id
        name
        description
      }
    `,
  },
);

export default RoleEditionOverview;
