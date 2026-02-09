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
import FormButtonContainer from '@common/form/FormButtonContainer';
import useDefaultValues from '../../../utils/hooks/useDefaultValues';
import useGranted, { KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS } from '../../../utils/hooks/useGranted';
import { useDynamicSchemaCreationValidation, useIsMandatoryAttribute, yupShapeConditionalRequired } from '../../../utils/hooks/useEntitySettings';
import MarkdownField from '../../../components/fields/MarkdownField';
import { FieldOption, fieldSpacingContainerStyle } from '../../../utils/field';
import ObjectAssigneeField from '@components/common/form/ObjectAssigneeField';
import ObjectParticipantField from '@components/common/form/ObjectParticipantField';
import CreatedByField from '@components/common/form/CreatedByField';
import useHelper from '../../../utils/hooks/useHelper';

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

export const DRAFTWORKPACE_TYPE = 'DraftWorkspace';

interface DraftFormProps {
  updater: (
    store: RecordSourceSelectorProxy,
    key: string,
  ) => void;
  onReset?: () => void;
  onCompleted?: () => void;
}

export interface DraftAddInput {
  name: string;
  description: string;
  objectAssignee: FieldOption[];
  objectParticipant: FieldOption[];
  createdBy: FieldOption | undefined;
  authorized_members?: AuthorizedMembersFieldValue;
}

const DraftCreationForm: React.FC<DraftFormProps> = ({ updater, onCompleted, onReset }) => {
  const { isFeatureEnable } = useHelper();
  const { t_i18n } = useFormatter();
  const { me: owner, settings } = useAuth();
  const { mandatoryAttributes } = useIsMandatoryAttribute(DRAFTWORKPACE_TYPE);
  const showAllMembersLine = !settings.platform_organization?.id;
  const canEditAuthorizedMembers = useGranted([KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS]);

  const basicShape = yupShapeConditionalRequired({
    name: Yup.string().trim().min(2, t_i18n('Name must be at least 2 characters')),
    description: Yup.string().nullable(),
    objectAssignee: Yup.array().nullable(),
    objectParticipant: Yup.array().nullable(),
    createdBy: Yup.object().nullable(),
    authorized_members: Yup.array().nullable(),
  }, mandatoryAttributes);
  const draftWorkspaceValidator = useDynamicSchemaCreationValidation(
    mandatoryAttributes,
    basicShape,
  );

  const [commitCreationMutation] = useApiMutation<DraftCreationMutation>(draftCreationMutation);

  const onSubmit: FormikConfig<DraftAddInput>['onSubmit'] = (values, { setSubmitting, setErrors, resetForm }) => {
    const input: DraftCreationMutation$variables['input'] = {
      name: values.name,
      description: values.description,
      objectAssignee: values.objectAssignee.map(({ value }) => value),
      objectParticipant: values.objectParticipant.map(({ value }) => value),
      createdBy: values.createdBy?.value,
      authorized_members: !values.authorized_members ? null : (
        values.authorized_members
          .filter((v) => v.accessRight !== 'none')
          .map((member) => ({
            id: member.value,
            access_right: member.accessRight,
            groups_restriction_ids: member.groupsRestriction?.length > 0
              ? member.groupsRestriction.map((group) => group.value)
              : undefined,
          }))
      ),
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

  const initialValues = useDefaultValues<DraftAddInput>(DRAFTWORKPACE_TYPE, {
    name: '',
    description: '',
    objectAssignee: [],
    objectParticipant: [],
    createdBy: undefined,
    authorized_members: undefined,
  });
  if (!canEditAuthorizedMembers) {
    delete initialValues.authorized_members;
  }

  return (
    <Formik<DraftAddInput>
      initialValues={initialValues}
      validationSchema={draftWorkspaceValidator}
      onSubmit={onSubmit}
      onReset={onReset}
    >
      {({ submitForm, handleReset, isSubmitting, setFieldValue }) => (
        <Form>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }} data-testid="draft-creation-form">
            <Field
              component={TextField}
              name="name"
              label={t_i18n('Name')}
              required={mandatoryAttributes.includes('name')}
              fullWidth
              data-testid="draft-creation-form-name-input"
            />
            {isFeatureEnable('DRAFT_METADATA') && (
              <>
                <Field
                  component={MarkdownField}
                  name="description"
                  label={t_i18n('Description')}
                  required={mandatoryAttributes.includes('description')}
                  fullWidth={true}
                  multiline={true}
                  rows="4"
                  style={fieldSpacingContainerStyle}
                  askAi={true}
                />
                <ObjectAssigneeField
                  name="objectAssignee"
                  style={fieldSpacingContainerStyle}
                  required={mandatoryAttributes.includes('objectAssignee')}
                />
                <ObjectParticipantField
                  name="objectParticipant"
                  style={fieldSpacingContainerStyle}
                  required={mandatoryAttributes.includes('objectParticipant')}
                />
                <CreatedByField
                  name="createdBy"
                  required={mandatoryAttributes.includes('createdBy')}
                  style={fieldSpacingContainerStyle}
                  setFieldValue={setFieldValue}
                />
              </>
            )}
            <Field
              name="authorized_members"
              component={AuthorizedMembersField}
              owner={owner}
              showAllMembersLine={showAllMembersLine}
              canDeactivate
              addMeUserWithAdminRights
              enableAccesses
              applyAccesses
            />
          </div>
          <FormButtonContainer>
            <Button
              variant="secondary"
              onClick={handleReset}
              disabled={isSubmitting}
            >
              {t_i18n('Cancel')}
            </Button>
            <Button
              onClick={submitForm}
              disabled={isSubmitting}
            >
              {t_i18n('Create')}
            </Button>
          </FormButtonContainer>
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
