import React, { FunctionComponent } from 'react';
import { createFragmentContainer, graphql, useMutation } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import { pick } from 'ramda';
import * as Yup from 'yup';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import MarkDownField from '../../../../components/MarkDownField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import SwitchField from '../../../../components/SwitchField';
import { GroupEditionOverview_group$data } from './__generated__/GroupEditionOverview_group.graphql';

export const groupMutationFieldPatch = graphql`
  mutation GroupEditionOverviewFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
  ) {
    groupEdit(id: $id) {
      fieldPatch(input: $input) {
        ...GroupEditionOverview_group
      }
    }
  }
`;

const groupEditionOverviewFocus = graphql`
  mutation GroupEditionOverviewFocusMutation($id: ID!, $input: EditContext!) {
    groupEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

const groupValidation = (t: (value: string) => string) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string().nullable(),
  default_assignation: Yup.bool(),
  auto_new_marking: Yup.bool(),
});

interface GroupEditionOverviewComponentProps {
  group: GroupEditionOverview_group$data,
  context:
  | readonly ({
    readonly focusOn: string | null;
    readonly name: string;
  } | null)[]
  | null;
}

const GroupEditionOverviewComponent: FunctionComponent<GroupEditionOverviewComponentProps> = ({ group, context }) => {
  const { t } = useFormatter();
  const [commitFocus] = useMutation(groupEditionOverviewFocus);
  const [commitFieldPatch] = useMutation(groupMutationFieldPatch);

  const initialValues = pick(
    ['name', 'description', 'default_assignation', 'auto_new_marking'],
    group,
  );

  const handleChangeFocus = (name: string) => {
    commitFocus({
      variables: {
        id: group.id,
        input: {
          focusOn: name,
        },
      },
    });
  };

  const handleSubmitField = (name: string, value: string) => {
    groupValidation(t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitFieldPatch({
          variables: { id: group.id, input: { key: name, value } },
        });
      })
      .catch(() => false);
  };

  return (
    <div>
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={groupValidation(t)}
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
              component={MarkDownField}
              name="description"
              label={t('Description')}
              fullWidth={true}
              multiline={true}
              rows={4}
              style={{ marginTop: 20 }}
              onFocus={handleChangeFocus}
              onSubmit={handleSubmitField}
              helperText={
                <SubscriptionFocus
                  context={context}
                  fieldName="description"
                />
              }
            />
            <Field
              component={SwitchField}
              type="checkbox"
              name="default_assignation"
              label={t('Granted by default at user creation')}
              containerstyle={{ marginTop: 20 }}
              onChange={handleSubmitField}
              helperText={
                <SubscriptionFocus
                  context={context}
                  fieldName="default_assignation"
                />
              }
            />
            <Field
              component={SwitchField}
              type="checkbox"
              name="auto_new_marking"
              label={t(
                'Automatically authorize this group to new marking definition',
              )}
              containerstyle={{ marginTop: 20 }}
              onChange={handleSubmitField}
              helperText={
                <SubscriptionFocus
                  context={context}
                  fieldName="auto_new_marking"
                />
              }
            />
          </Form>
        )}
      </Formik>
    </div>
  );
};

const GroupEditionOverview = createFragmentContainer(
  GroupEditionOverviewComponent,
  {
    group: graphql`
      fragment GroupEditionOverview_group on Group {
        id
        name
        description
        default_assignation
        auto_new_marking
      }
    `,
  },
);

export default GroupEditionOverview;
