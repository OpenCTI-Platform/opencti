import React, { FunctionComponent } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as R from 'ramda';
import * as Yup from 'yup';
import { SubscriptionFocus } from '../../../../components/Subscription';
import TextField from '../../../../components/TextField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { useFormatter } from '../../../../components/i18n';
import { RoleEditionOverview_role$data } from './__generated__/RoleEditionOverview_role.graphql';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { useSchemaEditionValidation, useMandatorySchemaAttributes } from '../../../../utils/hooks/useSchemaAttributes';

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

const OBJECT_TYPE = 'Role';

interface RoleEditionOverviewComponentProps {
  role: RoleEditionOverview_role$data,
  context: ReadonlyArray<{
    readonly focusOn?: string | null;
    readonly name: string;
  }> | null | undefined,
}

const RoleEditionOverviewComponent: FunctionComponent<RoleEditionOverviewComponentProps> = ({ role, context }) => {
  const { t_i18n } = useFormatter();
  const mandatoryAttributes = useMandatorySchemaAttributes(OBJECT_TYPE);
  const basicShape = {
    name: Yup.string(),
    description: Yup.string().nullable(),
  };
  const validator = useSchemaEditionValidation(
    OBJECT_TYPE,
    basicShape,
  );

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
    validator
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
        validationSchema={validator}
        onSubmit={() => {}}
      >
        {() => (
          <Form style={{ margin: '20px 0 20px 0' }}>
            <Field
              component={TextField}
              variant="standard"
              name="name"
              label={t_i18n('Name')}
              required={(mandatoryAttributes.includes('name'))}
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
              required={(mandatoryAttributes.includes('description'))}
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
