import { Field, Form, Formik } from 'formik';
import React, { FunctionComponent } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import * as Yup from 'yup';
import { ObjectShape } from 'yup';
import { GenericContext } from '@components/common/model/GenericContextModel';
import FormHelperText from '@mui/material/FormHelperText';
import { useTheme } from '@mui/styles';
import { InformationOutline } from 'mdi-material-ui';
import Tooltip from '@mui/material/Tooltip';
import { useFormatter } from '../../../../components/i18n';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { SubscriptionFocus } from '../../../../components/Subscription';
import SwitchField from '../../../../components/fields/SwitchField';
import TextField from '../../../../components/TextField';
import DashboardField from '../../common/form/DashboardField';
import { GroupEditionOverview_group$data } from './__generated__/GroupEditionOverview_group.graphql';
import GroupHiddenTypesField from './GroupHiddenTypesField';
import useFormEditor, { GenericData } from '../../../../utils/hooks/useFormEditor';
import type { Theme } from '../../../../components/Theme';

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
  context?: readonly (GenericContext | null)[] | null;

}
const GroupEditionOverviewComponent: FunctionComponent<GroupEditionOverviewComponentProps> = ({ group, context }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const basicShape: ObjectShape = {
    name: Yup.string().required(t_i18n('This field is required')),
    description: Yup.string().nullable(),
    default_assignation: Yup.bool(),
    auto_new_marking: Yup.bool(),
    group_confidence_level: Yup.number()
      .min(0, t_i18n('The value must be greater than or equal to 0'))
      .max(100, t_i18n('The value must be less than or equal to 100'))
      .required(t_i18n('This field is required')),
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
    no_creators: group.no_creators,
    restrict_delete: group.restrict_delete,
    default_dashboard: group.default_dashboard ? {
      value: group.default_dashboard.id,
      label: group.default_dashboard.name,
    } : null,
  };

  return (
    <div>
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={groupValidator}
        onSubmit={() => {
        }}
      >
        {() => (
          <Form style={{ marginTop: theme.spacing(2) }}>
            <Field
              component={TextField}
              name="name"
              label={t_i18n('Name')}
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
              label={t_i18n('Description')}
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
            <GroupHiddenTypesField groupData={group} />
            <Field
              component={SwitchField}
              type="checkbox"
              name="default_assignation"
              label={t_i18n('Granted by default at user creation')}
              containerstyle={{ marginTop: 20 }}
              onChange={editor.changeField}

            />
            <FormHelperText>
              <SubscriptionFocus
                context={context}
                fieldName="default_assignation"
              />
            </FormHelperText>
            <Field
              component={SwitchField}
              type="checkbox"
              name="auto_new_marking"
              label={<>
                {t_i18n(
                  'Automatically authorize this group to new marking definition',
                )}
                <Tooltip
                  title={t_i18n(
                    'The new marking definitions will also be shareable by this group.',
                  )}
                >
                  <InformationOutline
                    fontSize="small"
                    color="primary"
                    style={{ margin: '0 0 -5px 10px' }}
                  />
                </Tooltip>
              </>}
              containerstyle={{ marginTop: 20 }}
              onChange={editor.changeField}
            />
            <FormHelperText>
              <SubscriptionFocus
                context={context}
                fieldName="auto_new_marking"
              />
            </FormHelperText>
            <Field
              component={SwitchField}
              type="checkbox"
              name="no_creators"
              label={t_i18n(
                'Do not accumulate creators for the users of this group',
              )}
              containerstyle={{ marginTop: 20 }}
              onChange={editor.changeField}
            />
            <FormHelperText>
              <SubscriptionFocus
                context={context}
                fieldName="no_creators"
              />
            </FormHelperText>
            <Field
              component={SwitchField}
              type="checkbox"
              name="restrict_delete"
              label={t_i18n(
                'Do not allow these users to delete content created by other users',
              )}
              containerstyle={{ marginTop: 20 }}
              onChange={editor.changeField}
            />
            <FormHelperText>
              <SubscriptionFocus
                context={context}
                fieldName="restrict_delete"
              />
            </FormHelperText>
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
        no_creators
        restrict_delete
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
