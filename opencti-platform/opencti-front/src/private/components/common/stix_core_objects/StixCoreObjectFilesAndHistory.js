import React, { useState } from 'react';
import * as PropTypes from 'prop-types';
import {
  compose,
  filter,
  flatten,
  fromPairs,
  includes,
  map,
  uniq,
  zip,
} from 'ramda';
import * as Yup from 'yup';
import Grid from '@mui/material/Grid';
import withStyles from '@mui/styles/withStyles';
import { ConnectionHandler } from 'relay-runtime';
import MenuItem from '@mui/material/MenuItem';
import { graphql, createFragmentContainer } from 'react-relay';
import { Form, Formik, Field } from 'formik';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import FileExportViewer from '../files/FileExportViewer';
import FileImportViewer from '../files/FileImportViewer';
import SelectField from '../../../../components/SelectField';
import {
  commitMutation,
  MESSAGING$,
  QueryRenderer,
} from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import { markingDefinitionsLinesSearchQuery } from '../../settings/marking_definitions/MarkingDefinitionsLines';
import Loader from '../../../../components/Loader';
import StixCoreObjectHistory from './StixCoreObjectHistory';
import FileExternalReferencesViewer from '../files/FileExternalReferencesViewer';
import FilePendingViewer from '../files/FilePendingViewer';

const styles = () => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
  historyContainer: {
    marginTop: 80,
  },
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
});

export const stixCoreObjectFilesAndHistoryAskJobImportMutation = graphql`
  mutation StixCoreObjectFilesAndHistoryAskJobImportMutation(
    $fileName: ID!
    $connectorId: String
    $bypassEntityId: String
  ) {
    askJobImport(
      fileName: $fileName
      connectorId: $connectorId
      bypassEntityId: $bypassEntityId
    ) {
      ...FileLine_file
    }
  }
`;

export const stixCoreObjectFilesAndHistoryExportMutation = graphql`
  mutation StixCoreObjectFilesAndHistoryExportMutation(
    $id: ID!
    $format: String!
    $exportType: String!
    $maxMarkingDefinition: String
  ) {
    stixDomainObjectEdit(id: $id) {
      exportAsk(
        format: $format
        exportType: $exportType
        maxMarkingDefinition: $maxMarkingDefinition
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

const exportValidation = (t) => Yup.object().shape({
  format: Yup.string().required(t('This field is required')),
  type: Yup.string().required(t('This field is required')),
});

const importValidation = (t) => Yup.object().shape({
  connector_id: Yup.string().required(t('This field is required')),
});

const StixCoreObjectFilesAndHistory = ({
  id,
  entity,
  t,
  classes,
  connectorsExport,
  connectorsImport,
  withoutRelations,
  bypassEntityId,
}) => {
  const [fileToImport, setFileToImport] = useState(null);
  const [openExport, setOpenExport] = useState(false);
  const exportScopes = uniq(
    flatten(map((c) => c.connector_scope, connectorsExport)),
  );
  const exportConnsPerFormat = scopesConn(connectorsExport);
  // eslint-disable-next-line max-len
  const isExportActive = (format) => filter((x) => x.data.active, exportConnsPerFormat[format]).length > 0;
  const isExportPossible = filter((x) => isExportActive(x), exportScopes).length > 0;
  const handleOpenImport = (file) => setFileToImport(file);
  const handleCloseImport = () => setFileToImport(null);
  const handleOpenExport = () => setOpenExport(true);
  const handleCloseExport = () => setOpenExport(false);

  const onSubmitImport = (values, { setSubmitting, resetForm }) => {
    commitMutation({
      mutation: stixCoreObjectFilesAndHistoryAskJobImportMutation,
      variables: {
        fileName: fileToImport.id,
        connectorId: values.connector_id,
        bypassEntityId: bypassEntityId ? id : null,
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
    const maxMarkingDefinition = values.maxMarkingDefinition === 'none'
      ? null
      : values.maxMarkingDefinition;
    commitMutation({
      mutation: stixCoreObjectFilesAndHistoryExportMutation,
      variables: {
        id,
        format: values.format,
        exportType: values.type,
        maxMarkingDefinition,
      },
      updater: (store) => {
        const root = store.getRootField('stixDomainObjectEdit');
        const payloads = root.getLinkedRecords('exportAsk', {
          format: values.format,
          exportType: values.type,
          maxMarkingDefinition,
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
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        handleCloseExport();
        MESSAGING$.notifySuccess('Export successfully started');
      },
    });
  };

  const importConnsPerFormat = connectorsImport
    ? scopesConn(connectorsImport)
    : {};
  return (
    <div className={classes.container}>
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
        <FilePendingViewer
          entity={entity}
          handleOpenImport={handleOpenImport}
        />
        <FileExportViewer
          entity={entity}
          handleOpenExport={handleOpenExport}
          isExportPossible={isExportPossible}
        />
        <FileExternalReferencesViewer
          entity={entity}
          connectors={importConnsPerFormat}
          handleOpenImport={handleOpenImport}
        />
      </Grid>
      <div className={classes.historyContainer}>
        <StixCoreObjectHistory
          stixCoreObjectId={id}
          withoutRelations={withoutRelations}
        />
      </div>
      <Formik
        enableReinitialize={true}
        initialValues={{ connector_id: '' }}
        validationSchema={importValidation(t)}
        onSubmit={onSubmitImport}
        onReset={handleCloseImport}
      >
        {({ submitForm, handleReset, isSubmitting }) => (
          <Form style={{ margin: '0 0 20px 0' }}>
            <Dialog
              PaperProps={{ elevation: 1 }}
              open={fileToImport}
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
              </DialogContent>
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
      <div>
        <Formik
          enableReinitialize={true}
          initialValues={{
            format: '',
            type: 'full',
            maxMarkingDefinition: 'none',
          }}
          validationSchema={exportValidation(t)}
          onSubmit={onSubmitExport}
          onReset={handleCloseExport}
        >
          {({ submitForm, handleReset, isSubmitting }) => (
            <Form style={{ margin: '0 0 20px 0' }}>
              <Dialog
                PaperProps={{ elevation: 1 }}
                open={openExport}
                keepMounted={true}
                onClose={handleCloseExport}
                fullWidth={true}
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
                            containerstyle={{ marginTop: 20, width: '100%' }}
                          >
                            <MenuItem value="simple">
                              {t('Simple export (just the entity)')}
                            </MenuItem>
                            <MenuItem value="full">
                              {t('Full export (entity and first neighbours)')}
                            </MenuItem>
                          </Field>
                          <Field
                            component={SelectField}
                            variant="standard"
                            name="maxMarkingDefinition"
                            label={t('Max marking definition level')}
                            fullWidth={true}
                            containerstyle={{ marginTop: 20, width: '100%' }}
                          >
                            <MenuItem value="none">{t('None')}</MenuItem>
                            {map(
                              (markingDefinition) => (
                                <MenuItem
                                  key={markingDefinition.node.id}
                                  value={markingDefinition.node.id}
                                >
                                  {markingDefinition.node.definition}
                                </MenuItem>
                              ),
                              props.markingDefinitions.edges,
                            )}
                          </Field>
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
        connector_scope
        updated_at
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(StixCoreObjectFilesAndHistoryFragment);
