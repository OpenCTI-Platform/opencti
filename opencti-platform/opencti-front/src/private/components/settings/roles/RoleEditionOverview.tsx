import React, { FunctionComponent } from 'react';
import { createFragmentContainer, graphql, useMutation } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as R from 'ramda';
import * as Yup from 'yup';
import { SubscriptionFocus } from '../../../../components/Subscription';
import TextField from '../../../../components/TextField';
import MarkdownField from '../../../../components/MarkdownField';
import { useFormatter } from '../../../../components/i18n';
import HiddenTypesList from '../entity_settings/HiddenTypesList';
import { RoleEditionOverview_role$data } from './__generated__/RoleEditionOverview_role.graphql';

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
    readonly focusOn: string | null;
    readonly name: string;
  }> | null,
}

const RoleEditionOverviewComponent: FunctionComponent<RoleEditionOverviewComponentProps> = ({ role, context }) => {
  const { t } = useFormatter();
  const initialValues = R.pick(
    ['name', 'description'],
    role,
  );
  const [commitFocus] = useMutation(roleEditionOverviewFocus);
  const [commitFieldPatch] = useMutation(roleMutationFieldPatch);
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
    roleValidation(t)
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
        validationSchema={roleValidation(t)}
        onSubmit={() => {}}
      >
        {() => (
          <Form style={{ margin: '20px 0 20px 0' }}>
            <Field
              component={TextField}
              variant="standard"
              name="name"
              label={t('Name')}
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
              label={t('Description')}
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
            <HiddenTypesList role={role} />
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
        default_hidden_types
      }
    `,
  },
);

export default RoleEditionOverview;
