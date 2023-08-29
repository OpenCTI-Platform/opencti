import { Field, Form, Formik } from 'formik';
import React, { FunctionComponent } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import * as Yup from 'yup';
import { ObjectShape } from 'yup';
import { useFormatter } from '../../../../components/i18n';
import MarkdownField from '../../../../components/MarkdownField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import SwitchField from '../../../../components/SwitchField';
import TextField from '../../../../components/TextField';
import DashboardField from '../../common/form/DashboardField';
import { GroupEditionOverview_group$data } from './__generated__/GroupEditionOverview_group.graphql';
import GroupHiddenTypesField from './GroupHiddenTypesField';
import useFormEditor, { GenericData } from '../../../../utils/hooks/useFormEditor';

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

const groupMutationRelationAdd = graphql`
  mutation GroupEditionOverviewRelationAddMutation(
    $id: ID!
    $input: InternalRelationshipAddInput!
  ) {
    groupEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...GroupEditionOverview_group
        }
      }
    }
  }
`;

const groupMutationRelationDelete = graphql`
  mutation GroupEditionOverviewRelationDeleteMutation(
    $id: ID!
    $fromId: StixRef!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    groupEdit(id: $id) {
      relationDelete( 
        fromId: $fromId
        toId: $toId
        relationship_type: $relationship_type) {
          ...GroupEditionOverview_group
      }
    }
  }
`;

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

  const basicShape: ObjectShape = {
    name: Yup.string().required(t('This field is required')),
    description: Yup.string().nullable(),
    default_assignation: Yup.bool(),
    auto_new_marking: Yup.bool(),
  };

  const groupValidator = Yup.object().shape(basicShape);
  const queries = {
    fieldPatch: groupMutationFieldPatch,
    editionFocus: groupEditionOverviewFocus,
    relationAdd: groupMutationRelationAdd,
    relationDelete: groupMutationRelationDelete,
  };
  const editor = useFormEditor(group as unknown as GenericData, false, queries, groupValidator);

  const initialValues = {
    name: group.name,
    description: group.description,
    default_assignation: group.default_assignation,
    auto_new_marking: group.auto_new_marking,
    default_dashboard: group.default_dashboard ? {
      value: group.default_dashboard.id,
      label: group.default_dashboard.name,
    } : null,
  };

  return (
    <div>
      <Formik
        enableReinitialize={true}
        initialValues={initialValues as never}
        validationSchema={groupValidator}
        onSubmit={() => {
        }}
      >
        {() => (
          <Form style={{ margin: '20px 0 20px 0' }}>
            <Field
              component={TextField}
              name="name"
              label={t('Name')}
              fullWidth={true}
              onFocus={editor.changeFocus}
              onSubmit={editor.changeField}
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
              onFocus={editor.changeFocus}
              onSubmit={editor.changeField}
              helperText={
                <SubscriptionFocus
                  context={context}
                  fieldName="description"
                />
              }
            />
            <DashboardField
              onChange={editor.changeField}
              context={context}
            />
            <Field
              component={SwitchField}
              type="checkbox"
              name="default_assignation"
              label={t('Granted by default at user creation')}
              containerstyle={{ marginTop: 20 }}
              onChange={editor.changeField}
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
              onChange={editor.changeField}
              helperText={
                <SubscriptionFocus
                  context={context}
                  fieldName="auto_new_marking"
                />
              }
            />
            <GroupHiddenTypesField groupData={group} />
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
        default_dashboard {
          id
          name
          authorizedMembers {
            id
          }
        }
        ...GroupHiddenTypesField_group
      }
    `,
  },
);

export default GroupEditionOverview;
