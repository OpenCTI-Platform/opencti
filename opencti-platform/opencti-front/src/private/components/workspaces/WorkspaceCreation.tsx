import Button from '@common/button/Button';
import { FileUploadOutlined } from '@mui/icons-material';
import { Field, Form, Formik } from 'formik';
import { FormikConfig } from 'formik/dist/types';
import { BaseSyntheticEvent, useContext, useRef } from 'react';
import { graphql } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import * as Yup from 'yup';
import CreateEntityControlledDial from '../../../components/CreateEntityControlledDial';
import TextField from '../../../components/TextField';
import IconButton from '../../../components/common/button/IconButton';
import FormButtonContainer from '../../../components/common/form/FormButtonContainer';
import MarkdownField from '../../../components/fields/MarkdownField';
import { useFormatter } from '../../../components/i18n';
import { handleError, handleErrorInForm } from '../../../relay/environment';
import { resolveLink } from '../../../utils/Entity';
import Security from '../../../utils/Security';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import { UserContext } from '../../../utils/hooks/useAuth';
import { EXPLORE_EXUPDATE, INVESTIGATION_INUPDATE } from '../../../utils/hooks/useGranted';
import { insertNode } from '../../../utils/store';
import { isNotEmptyField } from '../../../utils/utils';
import VisuallyHiddenInput from '../common/VisuallyHiddenInput';
import Drawer from '../common/drawer/Drawer';
import { WorkspaceCreationImportMutation } from './__generated__/WorkspaceCreationImportMutation.graphql';
import { WorkspacesLinesPaginationQuery$variables } from './__generated__/WorkspacesLinesPaginationQuery.graphql';

const workspaceMutation = graphql`
  mutation WorkspaceCreationMutation($input: WorkspaceAddInput!) {
    workspaceAdd(input: $input) {
      id
      ...WorkspacesLine_node
    }
  }
`;

export const importMutation = graphql`
  mutation WorkspaceCreationImportMutation($file: Upload!) {
    workspaceConfigurationImport(file: $file)
  }
`;

const workspaceValidation = (t_i18n: (s: string) => string) => Yup.object().shape({
  name: Yup.string().trim().min(2, t_i18n('Name must be at least 2 characters')).required(t_i18n('This field is required')),
  description: Yup.string().nullable(),
});

interface WorkspaceCreationForm {
  name: string;
  description: string;
}

interface WorkspaceCreationProps {
  paginationOptions: WorkspacesLinesPaginationQuery$variables;
  type: string;
}

const WorkspaceCreation = ({ paginationOptions, type }: WorkspaceCreationProps) => {
  const { t_i18n } = useFormatter();
  const inputRef = useRef<HTMLInputElement | null>(null);
  const { settings, isXTMHubAccessible } = useContext(UserContext);
  const importFromHubUrl = isNotEmptyField(settings?.platform_xtmhub_url)
    ? `${settings.platform_xtmhub_url}/redirect/opencti_custom_dashboards?platform_id=${settings.id}`
    : '';

  const [commitImportMutation] = useApiMutation<WorkspaceCreationImportMutation>(importMutation);
  const [commitCreationMutation] = useApiMutation(workspaceMutation);
  const navigate = useNavigate();

  const handleImport = (event: BaseSyntheticEvent) => {
    const importedFile = event.target.files[0];
    commitImportMutation({
      variables: { file: importedFile },
      onCompleted: (data) => {
        if (inputRef.current) inputRef.current.value = ''; // Reset the input uploader ref
        navigate(
          `${resolveLink('Dashboard')}/${data.workspaceConfigurationImport}`,
        );
      },
      onError: (error) => {
        if (inputRef.current) inputRef.current.value = ''; // Reset the input uploader ref
        handleError(error);
      },
    });
  };

  const onSubmit: FormikConfig<WorkspaceCreationForm>['onSubmit'] = (values, { setSubmitting, resetForm, setErrors }) => {
    commitCreationMutation({
      variables: {
        input: {
          ...values,
          type,
        },
      },
      updater: (store) => {
        insertNode(
          store,
          'Pagination_workspaces',
          paginationOptions,
          'workspaceAdd',
        );
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

  const createInvestigationButton = (props: { onOpen: () => void }) => (
    <Security needs={[INVESTIGATION_INUPDATE]}>
      <CreateEntityControlledDial entityType="Investigation" {...props} />
    </Security>
  );

  const createDashboardButton = (props: { onOpen: () => void }) => (
    <Security needs={[EXPLORE_EXUPDATE]}>
      <>
        <IconButton
          value="import"
          size="default"
          variant="secondary"
          onClick={() => inputRef.current?.click()}
          data-testid="ImportDashboard"
          title={t_i18n('Import dashboard')}
        >
          <FileUploadOutlined fontSize="small" color="primary" />
        </IconButton>
        {isXTMHubAccessible && isNotEmptyField(importFromHubUrl) && (
          <Button
            gradient
            href={importFromHubUrl}
            target="_blank"
            title={t_i18n('Import from Hub')}
          >
            {t_i18n('Import from Hub')}
          </Button>
        )}
        <CreateEntityControlledDial entityType="Dashboard" {...props} />
      </>
    </Security>
  );

  return (
    <>
      <VisuallyHiddenInput type="file" accept="application/JSON" ref={inputRef} onChange={handleImport} />
      <Drawer
        title={t_i18n(`Create ${type}`)}
        controlledDial={(type === 'dashboard')
          ? createDashboardButton
          : createInvestigationButton
        }
      >
        {({ onClose }) => (
          <Formik
            initialValues={{
              name: '',
              description: '',
            }}
            validationSchema={workspaceValidation(t_i18n)}
            onSubmit={onSubmit}
            onReset={onClose}
          >
            {({ submitForm, handleReset, isSubmitting }) => (
              <Form>
                <Field
                  component={TextField}
                  name="name"
                  label={t_i18n('Name')}
                  fullWidth={true}
                />
                <Field
                  component={MarkdownField}
                  name="description"
                  label={t_i18n('Description')}
                  fullWidth={true}
                  multiline={true}
                  rows="4"
                  style={{ marginTop: 20 }}
                />
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
        )}
      </Drawer>
    </>
  );
};

export default WorkspaceCreation;
