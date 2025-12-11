import React from 'react';
import { Field, Form, Formik } from 'formik';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import MenuItem from '@mui/material/MenuItem';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import * as Yup from 'yup';
import ObjectMarkingField from '@components/common/form/ObjectMarkingField';
import ManageImportConnectorMessage from '@components/data/import/ManageImportConnectorMessage';
import { fileManagerAskJobImportMutation, fileManagerCreateDraftAskJobImportMutation } from '@components/common/files/FileManager';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { ImportWorksDrawerQuery, ImportWorksDrawerQuery$data } from '@components/common/files/__generated__/ImportWorksDrawerQuery.graphql';
import { fileWorksQuery } from '@components/common/files/ImportWorksDrawer';
import { ImportWorkbenchesContentFileLine_file$data } from '@components/data/import/__generated__/ImportWorkbenchesContentFileLine_file.graphql';
import { ImportFilesContentFileLine_file$data } from '@components/data/import/__generated__/ImportFilesContentFileLine_file.graphql';
import AuthorizedMembersField, { AuthorizedMembersFieldValue } from '@components/common/form/AuthorizedMembersField';
import { commitMutation, defaultCommitMutation } from '../../../../relay/environment';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import { resolveHasUserChoiceParsedCsvMapper } from '../../../../utils/csvMapperUtils';
import SelectField from '../../../../components/fields/SelectField';
import { useFormatter } from '../../../../components/i18n';
import useAuth from '../../../../utils/hooks/useAuth';

interface LaunchImportDialogProps {
  file: ImportWorkbenchesContentFileLine_file$data | ImportFilesContentFileLine_file$data;
  open: boolean;
  onClose: () => void;
  onSuccess?: () => void;
  isDraftContext?: boolean;
  queryRef: PreloadedQuery<ImportWorksDrawerQuery>
}

type ConnectorType = NonNullable<ImportWorksDrawerQuery$data['connectorsForImport']>[number];

const LaunchImportDialog: React.FC<LaunchImportDialogProps> = ({
  file,
  queryRef,
  open,
  onClose,
  onSuccess,
  isDraftContext = false,
}) => {
  const { t_i18n } = useFormatter();
  const { me: owner, settings } = useAuth();
  const showAllMembersLine = !settings.platform_organization?.id;
  const { connectorsForImport: connectors } = usePreloadedQuery<ImportWorksDrawerQuery>(fileWorksQuery, queryRef);
  const [selectedConnector, setSelectedConnector] = React.useState<ConnectorType | null>(null);
  const [hasUserChoiceCsvMapper, setHasUserChoiceCsvMapper] = React.useState(false);

  const handleSetCsvMapper = (_: UIEvent, csvMapper: string) => {
    try {
      const parsedCsvMapper = JSON.parse(csvMapper);
      const parsedRepresentations = JSON.parse(parsedCsvMapper.representations);
      const selectedCsvMapper = {
        ...parsedCsvMapper,
        representations: [...parsedRepresentations],
      };
      setHasUserChoiceCsvMapper(resolveHasUserChoiceParsedCsvMapper(selectedCsvMapper));
    } catch (_e) {
      setHasUserChoiceCsvMapper(false);
    }
  };

  const handleSelectConnector = (_: UIEvent, value: string) => {
    const connector = connectors?.find((c) => c?.id === value);
    setSelectedConnector(connector);
  };

  const onSubmitImport = (
    values: {
      connector_id: string;
      configuration: string;
      objectMarking: FieldOption[];
      validation_mode: string;
      authorizedMembers?: AuthorizedMembersFieldValue;
    },
    { setSubmitting, resetForm }: { setSubmitting: (isSubmitting: boolean) => void; resetForm: () => void },
  ) => {
    const { connector_id, configuration, objectMarking, validation_mode, authorizedMembers } = values;
    let config = configuration;

    // Dynamically inject the markings chosen by the user into the csv mapper
    const isCsvConnector = selectedConnector?.name === 'ImportCsv';
    if (isCsvConnector && configuration && objectMarking) {
      const parsedConfig = JSON.parse(configuration);
      if (typeof parsedConfig === 'object') {
        parsedConfig.markings = objectMarking.map((marking) => marking.value);
        config = JSON.stringify(parsedConfig);
      }
    }

    commitMutation({
      ...defaultCommitMutation,
      mutation: validation_mode === 'draft' ? fileManagerCreateDraftAskJobImportMutation : fileManagerAskJobImportMutation,
      variables: {
        fileName: file.id,
        connectorId: connector_id,
        configuration: config,
        validationMode: validation_mode,
        authorized_members: !authorizedMembers
          ? null
          : authorizedMembers
            .filter((v) => v.accessRight !== 'none')
            .map((member) => ({
              id: member.value,
              access_right: member.accessRight,
              groups_restriction_ids: member.groupsRestriction?.length > 0
                ? member.groupsRestriction.map((group) => group.value)
                : undefined,
            })),
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        onClose();
        if (onSuccess) {
          onSuccess();
        }
      },
    });
  };

  const importValidation = (configurations: boolean) => {
    const shape = {
      connector_id: Yup.string().required(t_i18n('This field is required')),
    };
    if (configurations) {
      return Yup.object().shape({
        ...shape,
        configuration: Yup.string().required(t_i18n('This field is required')),
      });
    }
    return Yup.object().shape(shape);
  };

  const invalidCsvMapper = selectedConnector?.name === 'ImportCsv'
    && selectedConnector?.configurations?.length === 0;

  return (
    <Formik
      enableReinitialize={true}
      initialValues={{
        connector_id: '',
        validation_mode: isDraftContext ? 'draft' : 'workbench',
        configuration: '',
        objectMarking: [],
      }}
      validationSchema={importValidation(!!selectedConnector?.configurations)}
      onSubmit={onSubmitImport}
      onReset={onClose}
    >
      {({ submitForm, handleReset, isSubmitting, setFieldValue, isValid, values }) => (
        <Form>
          <Dialog
            open={open}
            slotProps={{ paper: { elevation: 1 } }}
            keepMounted={true}
            onClose={() => handleReset()}
            fullWidth={true}
            onClick={(event) => event.stopPropagation()}
          >
            <DialogTitle>{t_i18n('Launch an import')}</DialogTitle>
            <DialogContent>
              <Field
                component={SelectField}
                variant="standard"
                name="connector_id"
                label={t_i18n('Connector')}
                fullWidth={true}
                containerstyle={{ width: '100%' }}
                onChange={handleSelectConnector}
              >
                {connectors?.map((connector) => {
                  const disabled = !file
                    || (connector?.connector_scope && connector?.connector_scope?.length > 0
                      && file?.metaData?.mimetype && !connector?.connector_scope?.includes(file?.metaData?.mimetype));
                  return (
                    <MenuItem
                      key={connector?.id}
                      value={connector?.id}
                      disabled={disabled || !connector?.active}
                    >
                      {connector?.name}
                    </MenuItem>
                  );
                })}
              </Field>
              {!isDraftContext && (
                <Field
                  component={SelectField}
                  variant="standard"
                  name="validation_mode"
                  label={t_i18n('Validation mode')}
                  fullWidth={true}
                  containerstyle={{ marginTop: 20, width: '100%' }}
                  setFieldValue={setFieldValue}
                >
                  <MenuItem value="workbench">Workbench</MenuItem>
                  <MenuItem value="draft">Draft</MenuItem>
                </Field>
              )}
              {values.validation_mode === 'draft' && (
                <Field
                  name="authorizedMembers"
                  component={AuthorizedMembersField}
                  owner={owner}
                  showAllMembersLine={showAllMembersLine}
                  canDeactivate
                  addMeUserWithAdminRights
                  enableAccesses
                  applyAccesses
                  style={fieldSpacingContainerStyle}
                />
              )}
              {selectedConnector?.configurations && selectedConnector?.configurations?.length > 0 ? (
                <Field
                  component={SelectField}
                  variant="standard"
                  name="configuration"
                  label={t_i18n('Configuration')}
                  fullWidth={true}
                  containerstyle={{ marginTop: 20, width: '100%' }}
                  onChange={handleSetCsvMapper}
                >
                  {selectedConnector?.configurations?.map((config) => (
                    <MenuItem key={config.id} value={config.configuration}>
                      {config.name}
                    </MenuItem>
                  ))}
                </Field>
              ) : (
                <ManageImportConnectorMessage name={selectedConnector?.name}/>
              )}
              {selectedConnector?.name === 'ImportCsv' && hasUserChoiceCsvMapper && (
                <ObjectMarkingField
                  name="objectMarking"
                  style={fieldSpacingContainerStyle}
                  setFieldValue={setFieldValue}
                />
              )}
            </DialogContent>
            <DialogActions>
              <Button onClick={handleReset} disabled={isSubmitting}>
                {t_i18n('Cancel')}
              </Button>
              <Button
                color="secondary"
                onClick={submitForm}
                disabled={isSubmitting || !isValid || invalidCsvMapper || !selectedConnector}
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

export default LaunchImportDialog;
