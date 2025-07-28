import React, { FunctionComponent } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as R from 'ramda';
import * as Yup from 'yup';
import { useTheme } from '@mui/styles';
import { SubscriptionFocus } from '../../../../components/Subscription';
import TextField from '../../../../components/TextField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { useFormatter } from '../../../../components/i18n';
import { RoleEditionOverview_role$data } from './__generated__/RoleEditionOverview_role.graphql';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import type { Theme } from '../../../../components/Theme';

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
