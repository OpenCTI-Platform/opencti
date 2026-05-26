import Button from '@common/button/Button';
import { FileUploadOutlined } from '@mui/icons-material';
import { Field, Form, Formik } from 'formik';
import { FormikConfig } from 'formik/dist/types';
import { useContext } from 'react';
import { graphql } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import * as Yup from 'yup';
import CreateEntityControlledDial from '../../../components/CreateEntityControlledDial';
import TextField from '../../../components/TextField';
import IconButton from '../../../components/common/button/IconButton';
import FormButtonContainer from '../../../components/common/form/FormButtonContainer';
import MarkdownField from '../../../components/fields/markdownField/MarkdownField';
import { useFormatter } from '../../../components/i18n';
import { handleError, handleErrorInForm } from '../../../relay/environment';
import { resolveLink } from '../../../utils/Entity';
import Security from '../../../utils/Security';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import { UserContext } from '../../../utils/hooks/useAuth';
import { EXPLORE_EXUPDATE, INVESTIGATION_INUPDATE } from '../../../utils/hooks/useGranted';
import useMarkdownCreationFilesInput from '../../../utils/markdown/useMarkdownCreationFilesInput';
import { insertNode } from '../../../utils/store';
import { isNotEmptyField } from '../../../utils/utils';
import Drawer from '../common/drawer/Drawer';
import { WorkspaceCreationImportMutation } from './__generated__/WorkspaceCreationImportMutation.graphql';
import { WorkspacesLinesPaginationQuery$variables } from './__generated__/WorkspacesLinesPaginationQuery.graphql';
import useDashboardImport from '../../../components/dashboard/import-export/useDashboardImport';
import DashboardHiddenImportInput from '../../../components/dashboard/import-export/DashboardHiddenImportInput';
import { Box, Switch } from '@mui/material';
import MenuItem from '@mui/material/MenuItem';

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
  autoReload: boolean;
  refreshRate: number;
}

interface WorkspaceCreationProps {
  paginationOptions: WorkspacesLinesPaginationQuery$variables;
  type: string;
}

export const REFRESH_INTERVALS = [
  { label: '1 minute', value: 60 },
  { label: '5 minutes', value: 300 },
  { label: '15 minutes', value: 900 },
  { label: '30 minutes', value: 1800 },
  { label: '1 hour', value: 3600 },
];

const WorkspaceCreation = ({ paginationOptions, type }: WorkspaceCreationProps) => {
  const { t_i18n } = useFormatter();
  const { settings, isXTMHubAccessible } = useContext(UserContext);
  const importFromHubUrl = isNotEmptyField(settings?.platform_xtmhub_url)
    ? `${settings.platform_xtmhub_url}/redirect/opencti_custom_dashboards?platform_id=${settings.id}`
    : '';
  const [commitImportMutation] = useApiMutation<WorkspaceCreationImportMutation>(importMutation);
  const navigate = useNavigate();

  const { buildCreationFilesInput, registerMarkdownImagesController } = useMarkdownCreationFilesInput();

  const handleImport = (file: File) => new Promise<void>((resolve, reject) => {
    commitImportMutation({
      variables: { file },
      onCompleted: (data) => {
        navigate(
          `${resolveLink('Dashboard')}/${data.workspaceConfigurationImport}`,
        );
        resolve();
      },
      onError: (error) => {
        handleError(error);
        reject();
      },
    });
  });
  const importHelpers = useDashboardImport({ onImport: handleImport });

  const [commitCreationMutation] = useApiMutation(workspaceMutation);

  const onSubmit: FormikConfig<WorkspaceCreationForm>['onSubmit'] = (values, { setSubmitting, resetForm, setErrors }) => {
    const refreshRateInSeconds = values.autoReload
      ? values.refreshRate
      : null;
    commitCreationMutation({
      variables: {
        input: {
          ...buildCreationFilesInput(),
          name: values.name,
          description: values.description,
          type,
          refresh_rate: refreshRateInSeconds,
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
          onClick={importHelpers.handleImport}
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
      <DashboardHiddenImportInput helpers={importHelpers} />
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
              autoReload: false,
              refreshRate: 60,
            }}
            validationSchema={workspaceValidation(t_i18n)}
            onSubmit={onSubmit}
            onReset={onClose}
          >
            {({ submitForm, handleReset, isSubmitting, values, setFieldValue }) => (
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
                  autoPersistOnBlur={false}
                  registerMarkdownImagesController={registerMarkdownImagesController}
                />
                {type === 'dashboard' && (
                  <Box mt={2}>
                    <Box display="flex" alignItems="center" justifyContent="space-between">
                      <span>{t_i18n('Auto-reload')}</span>
                      <Switch
                        checked={values.autoReload}
                        onChange={(e) => setFieldValue('autoReload', e.target.checked)}
                      />
                    </Box>
                    {values.autoReload && (
                      <Box mt={2}>
                        <Field
                          name="refreshRate"
                          component={TextField}
                          select
                          fullWidth
                          label={t_i18n('Interval')}
                        >
                          {REFRESH_INTERVALS.map((opt) => (
                            <MenuItem key={opt.value} value={opt.value}>
                              {opt.label}
                            </MenuItem>
                          ))}
                        </Field>
                      </Box>
                    )}
                  </Box>
                )}
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
