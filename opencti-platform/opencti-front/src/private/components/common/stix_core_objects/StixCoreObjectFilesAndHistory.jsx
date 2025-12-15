import React, { useState } from 'react';
import * as PropTypes from 'prop-types';
import { compose, filter, flatten, fromPairs, includes, map, uniq, zip } from 'ramda';
import * as Yup from 'yup';
import Grid from '@mui/material/Grid';
import withStyles from '@mui/styles/withStyles';
import { ConnectionHandler } from 'relay-runtime';
import MenuItem from '@mui/material/MenuItem';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@common/button/Button';
import { InfoOutlined } from '@mui/icons-material';
import Tooltip from '@mui/material/Tooltip';
import DraftWorkspaceViewer from '../files/draftWorkspace/DraftWorkspaceViewer';
import { CONTENT_MAX_MARKINGS_HELPERTEXT, CONTENT_MAX_MARKINGS_TITLE, fileManagerCreateDraftAskJobImportMutation } from '../files/FileManager';
import ManageImportConnectorMessage from '../../data/import/ManageImportConnectorMessage';
import ObjectMarkingField from '../form/ObjectMarkingField';
import FileExportViewer from '../files/FileExportViewer';
import FileImportViewer from '../files/FileImportViewer';
import SelectField from '../../../../components/fields/SelectField';
import { commitMutation, handleError, MESSAGING$ } from '../../../../relay/environment';
import inject18n, { useFormatter } from '../../../../components/i18n';
import StixCoreObjectHistory from './StixCoreObjectHistory';
import FileExternalReferencesViewer from '../files/FileExternalReferencesViewer';
import WorkbenchFileViewer from '../files/workbench/WorkbenchFileViewer';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { resolveHasUserChoiceParsedCsvMapper } from '../../../../utils/csvMapperUtils';
import useDraftContext from '../../../../utils/hooks/useDraftContext';
import useAuth from '../../../../utils/hooks/useAuth';
import AuthorizedMembersField from '../form/AuthorizedMembersField';

const styles = (theme) => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
  paper: {
    marginTop: theme.spacing(1),
    padding: '15px',
    borderRadius: 4,
  },
});

export const stixCoreObjectFilesAndHistoryAskJobImportMutation = graphql`
  mutation StixCoreObjectFilesAndHistoryAskJobImportMutation(
    $fileName: ID!
    $connectorId: String
    $bypassEntityId: String
    $configuration: String
    $validationMode: ValidationMode
  ) {
    askJobImport(
      fileName: $fileName
      connectorId: $connectorId
      bypassEntityId: $bypassEntityId
      configuration: $configuration
      validationMode: $validationMode
    ) {
      ...FileLine_file
    }
  }
`;

export const stixCoreObjectFilesAndHistoryExportMutation = graphql`
  mutation StixCoreObjectFilesAndHistoryExportMutation(
    $id: ID!
    $input: ExportAskInput!
  ) {
    stixDomainObjectEdit(id: $id) {
      exportAsk(
        input: $input
      ) {
        id
        name
        uploadStatus
        lastModifiedSinceMin
        metaData {
          messages {
            timestamp
            message
          }
          errors {
            timestamp
            message
          }
        }
      }
    }
  }
`;

export const scopesConn = (exportConnectors) => {
  const scopes = uniq(flatten(map((c) => c.connector_scope, exportConnectors)));
  const connectors = map((s) => {
    const filteredConnectors = filter(
      (e) => includes(s, e.connector_scope),
      exportConnectors,
    );
    return map(
      (x) => ({ data: { name: x.name, active: x.active } }),
      filteredConnectors,
    );
  }, scopes);
  const zipped = zip(scopes, connectors);
  return fromPairs(zipped);
};

const exportValidation = (t_i18n) => Yup.object().shape({
  format: Yup.string().trim().required(t_i18n('This field is required')),
  type: Yup.string().trim().required(t_i18n('This field is required')),
});

const importValidation = (t_i18n, configurations) => {
  const shape = {
    connector_id: Yup.string().trim().required(t_i18n('This field is required')),
  };
  if (configurations) {
    return Yup.object().shape({
      ...shape,
      configuration: Yup.string().trim().required(t_i18n('This field is required')),
    });
  }
  return Yup.object().shape(shape);
};

const StixCoreObjectFilesAndHistory = ({
  id,
  entity,
  classes,
  connectorsExport,
  connectorsImport,
  withoutRelations,
  bypassEntityId,
}) => {
  const { t_i18n } = useFormatter();
  const { me: owner, settings } = useAuth();
  const showAllMembersLine = !settings.platform_organization?.id;
  const draftContext = useDraftContext();
  const [fileToImport, setFileToImport] = useState(null);
  const [openExport, setOpenExport] = useState(false);
  const [selectedConnector, setSelectedConnector] = useState(null);
  const [selectedContentMaxMarkingsIds, setSelectedContentMaxMarkingsIds] = useState([]);
  const exportScopes = uniq(
    flatten(map((c) => c.connector_scope, connectorsExport)),
  );
  const exportConnsPerFormat = scopesConn(connectorsExport);

  const isExportActive = (format) => filter((x) => x.data.active, exportConnsPerFormat[format]).length > 0;
  const isExportPossible = filter((x) => isExportActive(x), exportScopes).length > 0;
  const handleOpenImport = (file) => setFileToImport(file);
  const handleCloseImport = () => {
    setFileToImport(null);
    setSelectedConnector(null);
  };
  const handleOpenExport = () => setOpenExport(true);
  const handleCloseExport = () => setOpenExport(false);
  const handleSelectedContentMaxMarkingsChange = (values) => setSelectedContentMaxMarkingsIds(values.map(({ value }) => value));
  const onSubmitImport = (values, { setSubmitting, resetForm }) => {
    const { connector_id, configuration, objectMarking, validation_mode, authorizedMembers } = values;
    let config = configuration;
    // Dynamically inject the markings chosen by the user into the csv mapper.
    const isCsvConnector = selectedConnector?.name === 'ImportCsv';
    if (isCsvConnector && configuration && objectMarking) {
      const parsedConfig = JSON.parse(configuration);
      if (typeof parsedConfig === 'object') {
        parsedConfig.user_chosen_markings = objectMarking.map((marking) => marking.value);
        config = JSON.stringify(parsedConfig);
      }
    }
    commitMutation({
      mutation: validation_mode === 'draft' ? fileManagerCreateDraftAskJobImportMutation : stixCoreObjectFilesAndHistoryAskJobImportMutation,
      variables: {
        fileName: fileToImport.id,
        connectorId: connector_id,
        bypassEntityId: bypassEntityId ? id : null,
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
        handleCloseImport();
        MESSAGING$.notifySuccess('Import successfully asked');
      },
    });
  };
  const onSubmitExport = (values, { setSubmitting, resetForm }) => {
    const contentMaxMarkings = values.contentMaxMarkings.map(({ value }) => value);
    const fileMarkings = values.fileMarkings.map(({ value }) => value);

    commitMutation({
      mutation: stixCoreObjectFilesAndHistoryExportMutation,
      variables: {
        id,
        input: {
          format: values.format,
          exportType: values.type,
          contentMaxMarkings,
          fileMarkings,
        },
      },
      updater: (store) => {
        const root = store.getRootField('stixDomainObjectEdit');
        const payloads = root.getLinkedRecords('exportAsk', {
          input: {
            format: values.format,
            exportType: values.type,
            contentMaxMarkings,
            fileMarkings,
          },
        });
        const entityPage = store.get(id);
        const conn = ConnectionHandler.getConnection(
          entityPage,
          'Pagination_exportFiles',
        );
        for (let index = 0; index < payloads.length; index += 1) {
          const payload = payloads[index];
          const newEdge = payload.setLinkedRecord(payload, 'node');
          ConnectionHandler.insertEdgeBefore(conn, newEdge);
        }
      },
      onError: (error) => {
        handleError(error);
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        handleCloseExport();
        MESSAGING$.notifySuccess('Export successfully started');
      },
    });
  };

  const connectors = connectorsImport.filter((n) => !n.only_contextual);
  const importConnsPerFormat = scopesConn(connectors);

  const handleSelectConnector = (_, value) => {
    setSelectedConnector(connectors.find((c) => c.id === value));
  };

  const invalidCsvMapper = selectedConnector?.name === 'ImportCsv'
    && selectedConnector?.configurations?.length === 0;
  const [hasUserChoiceCsvMapper, setHasUserChoiceCsvMapper] = useState(false);
  const onCsvMapperSelection = (option) => {
    const parsedOption = typeof option === 'string' ? JSON.parse(option) : option;
    const parsedRepresentations = JSON.parse(parsedOption.representations);
    const selectedCsvMapper = {
      ...parsedOption,
      representations: [...parsedRepresentations],
    };
    const hasUserChoiceCsvMapperRepresentations = resolveHasUserChoiceParsedCsvMapper(selectedCsvMapper);
    setHasUserChoiceCsvMapper(hasUserChoiceCsvMapperRepresentations);
  };
  return (
    <div className={classes.container} data-testid="sco-data-file-and-history">
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
      >
        <FileImportViewer
          entity={entity}
          connectors={importConnsPerFormat}
          handleOpenImport={handleOpenImport}
        />
        <FileExportViewer
          entity={entity}
          handleOpenExport={handleOpenExport}
          isExportPossible={isExportPossible}
        />
        <WorkbenchFileViewer
          entity={entity}
          handleOpenImport={handleOpenImport}
        />
        <DraftWorkspaceViewer entityId={entity.id} />
        <FileExternalReferencesViewer
          entity={entity}
          connectors={importConnsPerFormat}
          handleOpenImport={handleOpenImport}
        />
        <Grid item xs={12}>
          <StixCoreObjectHistory
            stixCoreObjectId={id}
            withoutRelations={withoutRelations}
          />
        </Grid>
      </Grid>
      <Formik
        enableReinitialize={true}
        initialValues={{ connector_id: '', validation_mode: draftContext ? 'draft' : 'workbench', configuration: '', objectMarking: [] }}
        validationSchema={importValidation(t_i18n, selectedConnector?.configurations?.length > 0)}
        onSubmit={onSubmitImport}
        onReset={handleCloseImport}
      >
        {({ submitForm, handleReset, isSubmitting, setFieldValue, isValid, values }) => (
          <Form style={{ margin: '0 0 20px 0' }}>
            <Dialog
              slotProps={{ paper: { elevation: 1 } }}
              open={fileToImport}
              keepMounted={true}
              onClose={() => handleReset()}
              fullWidth={true}
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
                  {connectorsImport.map((connector, i) => {
                    const disabled = !fileToImport
                      || (connector.connector_scope.length > 0
                        && !includes(
                          fileToImport.metaData.mimetype,
                          connector.connector_scope,
                        ));
                    return (
                      <MenuItem
                        key={i}
                        value={connector.id}
                        disabled={disabled || !connector.active}
                      >
                        {connector.name}
                      </MenuItem>
                    );
                  })}
                </Field>
                {!draftContext && (
                  <Field
                    component={SelectField}
                    variant="standard"
                    name="validation_mode"
                    label={t_i18n('Validation mode')}
                    fullWidth={true}
                    containerstyle={{ marginTop: 20, width: '100%' }}
                    setFieldValue={setFieldValue}
                  >
                    <MenuItem
                      key="workbench"
                      value="workbench"
                    >
                      Workbench
                    </MenuItem>
                    <MenuItem
                      key="draft"
                      value="draft"
                    >
                      Draft
                    </MenuItem>
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
                {selectedConnector?.configurations?.length > 0
                  ? (
                      <Field
                        component={SelectField}
                        variant="standard"
                        name="configuration"
                        label={t_i18n('Configuration')}
                        fullWidth={true}
                        containerstyle={{ marginTop: 20, width: '100%' }}
                        onChange={(_, value) => onCsvMapperSelection(value)}
                      >
                        {selectedConnector.configurations.map((config) => {
                          return (
                            <MenuItem
                              key={config.id}
                              value={config.configuration}
                            >
                              {config.name}
                            </MenuItem>
                          );
                        })}
                      </Field>
                    ) : <ManageImportConnectorMessage name={selectedConnector?.name} />
                }
                {selectedConnector?.name === 'ImportCsv'
                  && hasUserChoiceCsvMapper
                  && (
                    <>
                      <ObjectMarkingField
                        name="objectMarking"
                        style={fieldSpacingContainerStyle}
                        setFieldValue={setFieldValue}
                      />
                    </>
                  )
                }
              </DialogContent>
              <DialogActions>
                <Button variant="secondary" onClick={handleReset} disabled={isSubmitting}>
                  {t_i18n('Cancel')}
                </Button>
                <Button
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
      <div>
        <Formik
          enableReinitialize={true}
          initialValues={{
            format: '',
            type: 'full',
            contentMaxMarkings: [],
            fileMarkings: [],
          }}
          validationSchema={exportValidation(t_i18n)}
          onSubmit={onSubmitExport}
          onReset={handleCloseExport}
        >
          {({ submitForm, handleReset, isSubmitting, setFieldValue }) => (
            <Form style={{ margin: '0 0 20px 0' }}>
              <Dialog
                slotProps={{ paper: { elevation: 1 } }}
                open={openExport}
                keepMounted={true}
                onClose={handleCloseExport}
                fullWidth={true}
                data-testid="StixCoreObjectFilesAndHistoryExportDialog"
              >
                <DialogTitle>
                  {t_i18n('Generate an export')}
                  <Tooltip title={t_i18n('Your max shareable markings will be applied to the content max markings')}>
                    <InfoOutlined sx={{ paddingLeft: 1 }} fontSize="small" />
                  </Tooltip>
                </DialogTitle>
                <DialogContent>
                  <Field
                    component={SelectField}
                    variant="standard"
                    name="format"
                    label={t_i18n('Export format')}
                    fullWidth={true}
                    containerstyle={{ width: '100%' }}
                  >
                    {exportScopes.map((value, i) => (
                      <MenuItem
                        key={i}
                        value={value}
                        disabled={!isExportActive(value)}
                      >
                        {value}
                      </MenuItem>
                    ))}
                  </Field>
                  <Field
                    component={SelectField}
                    variant="standard"
                    name="type"
                    label={t_i18n('Export type')}
                    fullWidth={true}
                    containerstyle={fieldSpacingContainerStyle}
                  >
                    <MenuItem value="simple">
                      {t_i18n('Simple export (just the entity)')}
                    </MenuItem>
                    <MenuItem value="full">
                      {t_i18n('Full export (entity and first neighbours)')}
                    </MenuItem>
                  </Field>
                  <ObjectMarkingField
                    name="contentMaxMarkings"
                    label={t_i18n(CONTENT_MAX_MARKINGS_TITLE)}
                    onChange={(_, values) => handleSelectedContentMaxMarkingsChange(values)}
                    style={fieldSpacingContainerStyle}
                    setFieldValue={setFieldValue}
                    limitToMaxSharing
                    helpertext={t_i18n(CONTENT_MAX_MARKINGS_HELPERTEXT)}
                  />
                  <ObjectMarkingField
                    name="fileMarkings"
                    label={t_i18n('File marking definition levels')}
                    filterTargetIds={selectedContentMaxMarkingsIds}
                    style={fieldSpacingContainerStyle}
                    setFieldValue={setFieldValue}
                  />
                </DialogContent>
                <DialogActions>
                  <Button variant="secondary" onClick={handleReset} disabled={isSubmitting}>
                    {t_i18n('Cancel')}
                  </Button>
                  <Button
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
      </div>
    </div>
  );
};

StixCoreObjectFilesAndHistory.propTypes = {
  nsdt: PropTypes.func,
  id: PropTypes.string.isRequired,
  entity: PropTypes.object.isRequired,
  connectorsExport: PropTypes.array.isRequired,
  connectorsImport: PropTypes.array.isRequired,
  withoutRelations: PropTypes.bool,
  bypassEntityId: PropTypes.bool,
};

const StixCoreObjectFilesAndHistoryFragment = createFragmentContainer(
  StixCoreObjectFilesAndHistory,
  {
    connectorsExport: graphql`
      fragment StixCoreObjectFilesAndHistory_connectorsExport on Connector
      @relay(plural: true) {
        id
        name
        active
        connector_scope
        updated_at
      }
    `,
    connectorsImport: graphql`
      fragment StixCoreObjectFilesAndHistory_connectorsImport on Connector
      @relay(plural: true) {
        id
        name
        active
        only_contextual
        connector_scope
        updated_at
        configurations {
          id
          name
          configuration
        }
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(StixCoreObjectFilesAndHistoryFragment);
