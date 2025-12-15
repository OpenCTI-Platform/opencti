import React, { useState } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
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
import { useInitCreateRelationshipContext } from '../stix_core_relationships/CreateRelationshipContextProvider';
import DraftWorkspaceViewer from './draftWorkspace/DraftWorkspaceViewer';
import ObjectMarkingField from '../form/ObjectMarkingField';
import FileExportViewer from './FileExportViewer';
import FileImportViewer from './FileImportViewer';
import SelectField from '../../../../components/fields/SelectField';
import { commitMutation, handleErrorInForm, MESSAGING$, QueryRenderer } from '../../../../relay/environment';
import inject18n, { useFormatter } from '../../../../components/i18n';
import { markingDefinitionsLinesSearchQuery } from '../../settings/MarkingDefinitionsQuery';
import Loader from '../../../../components/Loader';
import FileExternalReferencesViewer from './FileExternalReferencesViewer';
import WorkbenchFileViewer from './workbench/WorkbenchFileViewer';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import PictureManagementViewer from './PictureManagementViewer';
import { resolveHasUserChoiceParsedCsvMapper } from '../../../../utils/csvMapperUtils';

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

export const CONTENT_MAX_MARKINGS_TITLE = 'Content max marking definition levels';
export const CONTENT_MAX_MARKINGS_HELPERTEXT = 'Entities with higher marking definition levels won\'t be included in the file content.';

export const fileManagerAskJobImportMutation = graphql`
  mutation FileManagerAskJobImportMutation(
    $fileName: ID!
    $connectorId: String
    $configuration: String
    $bypassValidation: Boolean
    $forceValidation: Boolean
    $validationMode: ValidationMode
  ) {
    askJobImport(
      fileName: $fileName
      connectorId: $connectorId
      configuration: $configuration
      bypassValidation: $bypassValidation
      forceValidation: $forceValidation
      validationMode: $validationMode
    ) {
      ...FileLine_file
    }
  }
`;

export const fileManagerCreateDraftAskJobImportMutation = graphql`
  mutation FileManagerCreateDraftAskJobImportMutation(
    $fileName: ID!
    $connectorId: String
    $configuration: String
    $bypassValidation: Boolean
    $forceValidation: Boolean
    $validationMode: ValidationMode
    $authorized_members: [MemberAccessInput!]
  ) {
    createDraftAndAskJobImport(
      fileName: $fileName
      connectorId: $connectorId
      configuration: $configuration
      bypassValidation: $bypassValidation
      forceValidation: $forceValidation
      validationMode: $validationMode
      authorized_members: $authorized_members
    ) {
      ...FileLine_file
    }
  }
`;

export const fileManagerExportMutation = graphql`
  mutation FileManagerExportMutation(
    $id: ID!
    $input: ExportAskInput!
  ) {
    stixCoreObjectEdit(id: $id) {
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

const FileManager = ({
  id,
  entity,
  t,
  classes,
  connectorsExport,
  connectorsImport,
  isArtifact,
  directDownload = false,
}) => {
  useInitCreateRelationshipContext();

  const { t_i18n } = useFormatter();
  const [fileToImport, setFileToImport] = useState(null);
  const [openExport, setOpenExport] = useState(false);
  const [selectedConnector, setSelectedConnector] = useState(null);
  const [selectedContentMaxMarkingsIds, setSelectedContentMaxMarkingsIds] = useState([]);
  const handleSelectedContentMaxMarkingsChange = (values) => setSelectedContentMaxMarkingsIds(values.map(({ value }) => value));
  const exportScopes = uniq(
    flatten(map((c) => c.connector_scope, connectorsExport)),
  );
  const exportConnsPerFormat = scopesConn(connectorsExport);

  const isExportActive = (format) => filter((x) => x.data.active, exportConnsPerFormat[format]).length > 0;
  const isExportPossible = filter((x) => isExportActive(x), exportScopes).length > 0;
  const handleOpenImport = (file) => setFileToImport(file);
  const handleCloseImport = () => setFileToImport(null);
  const handleOpenExport = () => setOpenExport(true);
  const handleCloseExport = () => setOpenExport(false);

  const onSubmitImport = (values, { setSubmitting, resetForm }) => {
    const { connector_id, configuration, objectMarking } = values;
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
      mutation: fileManagerAskJobImportMutation,
      variables: {
        fileName: fileToImport.id,
        connectorId: connector_id,
        configuration: config,
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        handleCloseImport();
        MESSAGING$.notifySuccess('Import successfully asked');
      },
    });
  };

  const onSubmitExport = (values, { setSubmitting, setErrors, resetForm }) => {
    const contentMaxMarkings = values.contentMaxMarkings.map(({ value }) => value);
    const fileMarkings = values.fileMarkings.map(({ value }) => value);
    commitMutation({
      mutation: fileManagerExportMutation,
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
        const root = store.getRootField('stixCoreObjectEdit');
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
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        handleCloseExport();
        MESSAGING$.notifySuccess('Export successfully started');
      },
    });
  };

  const connectors = connectorsImport
    .filter((n) => !n.only_contextual)
    .filter((n) => !R.isEmpty(n.configurations));
  const importConnsPerFormat = scopesConn(connectors);

  const handleSelectConnector = (_, value) => {
    setSelectedConnector(connectors.find((c) => c.id === value));
  };

  const hasPictureManagement = [
    'Threat-Actor-Group',
    'Threat-Actor-Individual',
    'Intrusion-Set',
    'Tool',
    'Individual',
    'Organization',
    'Malware',
  ].includes(entity.entity_type);

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
    <div className={classes.container} data-testid="FileManager">
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
      >
        <FileImportViewer
          entity={entity}
          connectors={importConnsPerFormat}
          handleOpenImport={handleOpenImport}
          isArtifact={isArtifact}
          directDownload={directDownload}
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
          handleOpenImport={handleOpenImport}
        />
        {hasPictureManagement && <PictureManagementViewer entity={entity} />}
      </Grid>
      <div>
        <Formik
          enableReinitialize={true}
          initialValues={{ connector_id: '', configuration: '', objectMarking: [] }}
          validationSchema={importValidation(
            t,
            selectedConnector?.configurations?.length > 0,
          )}
          onSubmit={onSubmitImport}
          onReset={handleCloseImport}
        >
          {({ submitForm, handleReset, isSubmitting, setFieldValue }) => (
            <Form style={{ margin: '0 0 20px 0' }}>
              <Dialog
                slotProps={{ paper: { elevation: 1 } }}
                open={!!fileToImport}
                keepMounted={true}
                onClose={handleCloseImport}
                fullWidth={true}
              >
                <DialogTitle>{t('Launch an import')}</DialogTitle>
                <DialogContent>
                  <Field
                    component={SelectField}
                    variant="standard"
                    name="connector_id"
                    label={t('Connector')}
                    fullWidth={true}
                    containerstyle={{ width: '100%' }}
                    onChange={handleSelectConnector}
                  >
                    {(connectorsImport || []).map((connector, i) => {
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
                  {selectedConnector?.configurations?.length > 0 && (
                    <Field
                      component={SelectField}
                      variant="standard"
                      name="configuration"
                      label={t('Configuration')}
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
                  )}
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
                    {t('Cancel')}
                  </Button>
                  <Button
                    onClick={submitForm}
                    disabled={isSubmitting}
                  >
                    {t('Create')}
                  </Button>
                </DialogActions>
              </Dialog>
            </Form>
          )}
        </Formik>
      </div>
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
          {({ submitForm, handleReset, isSubmitting, resetForm, setFieldValue }) => (
            <Form style={{ margin: '0 0 20px 0' }}>
              <Dialog
                slotProps={{ paper: { elevation: 1 } }}
                open={openExport}
                keepMounted={true}
                onClose={resetForm}
                fullWidth={true}
                data-testid="FileManagerExportDialog"
              >
                <DialogTitle>{t('Generate an export')}</DialogTitle>
                <QueryRenderer
                  query={markingDefinitionsLinesSearchQuery}
                  variables={{ first: 200 }}
                  render={({ props }) => {
                    if (props && props.markingDefinitions) {
                      return (
                        <DialogContent>
                          <Field
                            component={SelectField}
                            variant="standard"
                            name="format"
                            label={t('Export format')}
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
                            label={t('Export type')}
                            fullWidth={true}
                            containerstyle={fieldSpacingContainerStyle}
                          >
                            <MenuItem value="simple">
                              {t('Simple export (just the entity)')}
                            </MenuItem>
                            <MenuItem value="full">
                              {t('Full export (entity and first neighbours)')}
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
                      );
                    }
                    return <Loader variant="inElement" />;
                  }}
                />
                <DialogActions>
                  <Button onClick={handleReset} disabled={isSubmitting}>
                    {t('Cancel')}
                  </Button>
                  <Button
                    color="secondary"
                    onClick={submitForm}
                    disabled={isSubmitting}
                  >
                    {t('Create')}
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

FileManager.propTypes = {
  nsdt: PropTypes.func,
  id: PropTypes.string.isRequired,
  entity: PropTypes.object.isRequired,
  connectorsExport: PropTypes.array.isRequired,
  connectorsImport: PropTypes.array.isRequired,
};

const FileManagerFragment = createFragmentContainer(FileManager, {
  connectorsExport: graphql`
    fragment FileManager_connectorsExport on Connector @relay(plural: true) {
      id
      name
      active
      connector_scope
      updated_at
    }
  `,
  connectorsImport: graphql`
    fragment FileManager_connectorsImport on Connector @relay(plural: true) {
      id
      name
      active
      connector_scope
      updated_at
      configurations {
        id
        name
        configuration
      }
    }
  `,
});

export default compose(inject18n, withStyles(styles))(FileManagerFragment);
