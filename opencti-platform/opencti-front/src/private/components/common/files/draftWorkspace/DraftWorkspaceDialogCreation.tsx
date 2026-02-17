import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import DialogActions from '@mui/material/DialogActions';
import { Field, Form, Formik } from 'formik';
import { FormikConfig } from 'formik/dist/types';
import { FunctionComponent } from 'react';
import { graphql } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { DraftsLinesPaginationQuery$variables } from '@components/drafts/__generated__/DraftsLinesPaginationQuery.graphql';
import AuthorizedMembersField from '@components/common/form/AuthorizedMembersField';
import * as Yup from 'yup';
import { useFormatter } from '../../../../../components/i18n';
import TextField from '../../../../../components/TextField';
import { handleErrorInForm } from '../../../../../relay/environment';
import { fieldSpacingContainerStyle } from '../../../../../utils/field';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import useAuth from '../../../../../utils/hooks/useAuth';
import { insertNode } from '../../../../../utils/store';
import { DraftWorkspaceDialogCreationMutation, DraftWorkspaceDialogCreationMutation$variables } from './__generated__/DraftWorkspaceDialogCreationMutation.graphql';
import MarkdownField from '../../../../../components/fields/MarkdownField';
import ObjectAssigneeField from '@components/common/form/ObjectAssigneeField';
import ObjectParticipantField from '@components/common/form/ObjectParticipantField';
import CreatedByField from '@components/common/form/CreatedByField';
import useHelper from '../../../../../utils/hooks/useHelper';
import { useDynamicSchemaCreationValidation, useIsMandatoryAttribute, yupShapeConditionalRequired } from '../../../../../utils/hooks/useEntitySettings';
import { DraftAddInput, DRAFTWORKSPACE_TYPE } from '@components/drafts/DraftCreation';
import useDefaultValues from '../../../../../utils/hooks/useDefaultValues';

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

const DraftWorkspaceDialogCreation: FunctionComponent<DraftWorkspaceCreationProps> = ({
  openCreate,
  handleCloseCreate,
  entityId,
  paginationOptions,
}) => {
  const { isFeatureEnable } = useHelper();
  const { t_i18n } = useFormatter();
  const { me: owner, settings } = useAuth();
  const { mandatoryAttributes } = useIsMandatoryAttribute(DRAFTWORKSPACE_TYPE);
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

  const onSubmit: FormikConfig<DraftAddInput>['onSubmit'] = (values, { setSubmitting, setErrors, resetForm }) => {
    const input: DraftWorkspaceDialogCreationMutation$variables['input'] = {
      name: values.name,
      entity_id: entityId,
      description: values.description,
      objectAssignee: values.objectAssignee.map(({ value }) => value),
      objectParticipant: values.objectParticipant.map(({ value }) => value),
      createdBy: values.createdBy?.value,
      authorized_members: !values.authorized_members
        ? null
        : values.authorized_members
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

  const initialValues = useDefaultValues<DraftAddInput>(DRAFTWORKSPACE_TYPE, {
    name: '',
    description: '',
    objectAssignee: [],
    objectParticipant: [],
    createdBy: undefined,
    authorized_members: undefined,
  });

  return (
    <Formik<DraftAddInput>
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={draftWorkspaceValidator}
      onSubmit={onSubmit}
      onReset={handleCloseCreate}
    >
      {({ submitForm, handleReset, isSubmitting, setFieldValue }) => (
        <Form>
          <Dialog
            open={!!openCreate}
            onClose={handleCloseCreate}
            title={t_i18n('Create a Draft')}
          >
            <Field
              component={TextField}
              variant="standard"
              name="name"
              label={t_i18n('Name')}
              fullWidth
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
              style={fieldSpacingContainerStyle}
            />
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
