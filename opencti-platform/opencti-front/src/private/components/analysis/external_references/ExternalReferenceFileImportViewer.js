import React, { useEffect, useState } from 'react';
import * as PropTypes from 'prop-types';
import { compose, includes } from 'ramda';
import { graphql, createRefetchContainer } from 'react-relay';
import { interval } from 'rxjs';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import withStyles from '@mui/styles/withStyles';
import List from '@mui/material/List';
import { Field, Form, Formik } from 'formik';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import MenuItem from '@mui/material/MenuItem';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import * as Yup from 'yup';
import FileLine from '../../common/files/FileLine';
import { TEN_SECONDS } from '../../../../utils/Time';
import FileUploader from '../../common/files/FileUploader';
import inject18n from '../../../../components/i18n';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';
import { fileManagerAskJobImportMutation } from '../../common/files/FileManager';
import SelectField from '../../../../components/SelectField';

const interval$ = interval(TEN_SECONDS);

const styles = () => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    marginTop: -7,
    padding: '10px 15px 10px 15px',
    borderRadius: 6,
  },
});

const importValidation = (t) => Yup.object().shape({
  connector_id: Yup.string().required(t('This field is required')),
});

const ExternalReferenceFileImportViewerBase = ({
  externalReference,
  disableImport,
  connectors,
  relay,
  t,
  classes,
  connectorsImport,
}) => {
  const [fileToImport, setFileToImport] = useState(null);
  const { id, importFiles } = externalReference;
  const { edges } = importFiles;
  const handleOpenImport = (file) => setFileToImport(file);
  const handleCloseImport = () => setFileToImport(null);
  const onSubmitImport = (values, { setSubmitting, resetForm }) => {
    commitMutation({
      mutation: fileManagerAskJobImportMutation,
      variables: {
        fileName: fileToImport.id,
        connectorId: values.connector_id,
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        handleCloseImport();
        MESSAGING$.notifySuccess('Import successfully asked');
      },
    });
  };

  useEffect(() => {
    // Refresh the export viewer every interval
    const subscription = interval$.subscribe(() => {
      relay.refetch({ id });
    });
    return function cleanup() {
      subscription.unsubscribe();
    };
  });
  return (
    <React.Fragment>
      <div style={{ height: '100%' }} className="break">
        <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
          {t('Uploaded files')}
        </Typography>
        <div style={{ float: 'left', marginTop: -17 }}>
          <FileUploader
            entityId={id}
            onUploadSuccess={() => relay.refetch({ id })}
          />
        </div>
        <div className="clearfix" />
        <Paper classes={{ root: classes.paper }} variant="outlined">
          {edges.length ? (
            <List>
              {edges.map((file) => (
                <FileLine
                  key={file.node.id}
                  dense={true}
                  disableImport={disableImport}
                  file={file.node}
                  connectors={
                    connectors && connectors[file.node.metaData.mimetype]
                  }
                  handleOpenImport={handleOpenImport}
                />
              ))}
            </List>
          ) : (
            <div style={{ display: 'table', height: '100%', width: '100%' }}>
              <span
                style={{
                  display: 'table-cell',
                  verticalAlign: 'middle',
                  textAlign: 'center',
                }}
              >
                {t('No file for the moment')}
              </span>
            </div>
          )}
        </Paper>
      </div>
      <div>
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
      </div>
    </React.Fragment>
  );
};

const ExternalReferenceFileImportViewerComponent = compose(
  inject18n,
  withStyles(styles),
)(ExternalReferenceFileImportViewerBase);

const ExternalReferenceFileImportViewerRefetchQuery = graphql`
  query ExternalReferenceFileImportViewerRefetchQuery($id: String!) {
    externalReference(id: $id) {
      ...ExternalReferenceFileImportViewer_entity
    }
  }
`;

const ExternalReferenceFileImportViewer = createRefetchContainer(
  ExternalReferenceFileImportViewerComponent,
  {
    externalReference: graphql`
      fragment ExternalReferenceFileImportViewer_entity on ExternalReference {
        id
        entity_type
        importFiles(first: 1000) @connection(key: "Pagination_importFiles") {
          edges {
            node {
              id
              ...FileLine_file
              metaData {
                mimetype
              }
            }
          }
        }
      }
    `,
    connectorsImport: graphql`
      fragment ExternalReferenceFileImportViewer_connectorsImport on Connector
      @relay(plural: true) {
        id
        name
        active
        connector_scope
        updated_at
      }
    `,
  },
  ExternalReferenceFileImportViewerRefetchQuery,
);

ExternalReferenceFileImportViewer.propTypes = {
  entity: PropTypes.object,
  disableImport: PropTypes.bool,
  connectors: PropTypes.object,
};

export default ExternalReferenceFileImportViewer;
