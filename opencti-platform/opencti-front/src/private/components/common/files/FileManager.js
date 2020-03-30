import React, { useState } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
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
import Grid from '@material-ui/core/Grid';
import { withStyles } from '@material-ui/core';
import { ConnectionHandler } from 'relay-runtime';
import MenuItem from '@material-ui/core/MenuItem';
import { createFragmentContainer } from 'react-relay';
import { Form, Formik, Field } from 'formik';
import Dialog from '@material-ui/core/Dialog';
import DialogTitle from '@material-ui/core/DialogTitle';
import DialogContent from '@material-ui/core/DialogContent';
import DialogActions from '@material-ui/core/DialogActions';
import Button from '@material-ui/core/Button';
import FileExportViewer from './FileExportViewer';
import FileImportViewer from './FileImportViewer';
import SelectField from '../../../../components/SelectField';
import {
  commitMutation,
  MESSAGING$,
  QueryRenderer,
} from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import { markingDefinitionsLinesSearchQuery } from '../../settings/marking_definitions/MarkingDefinitionsLines';
import Loader from '../../../../components/Loader';

const styles = () => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
});

export const FileManagerExportMutation = graphql`
  mutation FileManagerExportMutation(
    $id: ID!
    $format: String!
    $exportType: String!
    $maxMarkingDefinition: String
  ) {
    stixDomainEntityEdit(id: $id) {
      exportAsk(
        format: $format
        exportType: $exportType
        maxMarkingDefinition: $maxMarkingDefinition
      ) {
        id
        name
        uploadStatus
        lastModifiedSinceMin
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

const FileManager = ({
  id,
  entity,
  t,
  classes,
  connectorsExport,
  connectorsImport,
}) => {
  const [openExport, setOpenExport] = useState(false);
  const exportScopes = uniq(
    flatten(map((c) => c.connector_scope, connectorsExport)),
  );
  const exportConnsPerFormat = scopesConn(connectorsExport);
  // eslint-disable-next-line max-len
  const isExportActive = (format) => filter((x) => x.data.active, exportConnsPerFormat[format]).length > 0;
  const isExportPossible = filter((x) => isExportActive(x), exportScopes).length > 0;
  const handleOpenExport = () => setOpenExport(true);
  const handleCloseExport = () => setOpenExport(false);

  const onSubmit = (values, { setSubmitting, resetForm }) => {
    const maxMarkingDefinition = values.maxMarkingDefinition === 'none'
      ? null
      : values.maxMarkingDefinition;
    commitMutation({
      mutation: FileManagerExportMutation,
      variables: {
        id,
        format: values.format,
        exportType: values.type,
        maxMarkingDefinition,
      },
      updater: (store) => {
        const root = store.getRootField('stixDomainEntityEdit');
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
        <FileImportViewer entity={entity} connectors={importConnsPerFormat} />
        <FileExportViewer
          entity={entity}
          handleOpenExport={handleOpenExport}
          isExportPossible={isExportPossible}
        />
      </Grid>
      <div>
        <Formik
          enableReinitialize={true}
          initialValues={{
            format: '',
            type: 'full',
            maxMarkingDefinition: 'none',
          }}
          validationSchema={exportValidation(t)}
          onSubmit={onSubmit}
          onReset={handleCloseExport}
        >
          {({ submitForm, handleReset, isSubmitting }) => (
            <Form style={{ margin: '0 0 20px 0' }}>
              <Dialog
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
                  <Button
                    onClick={handleReset}
                    disabled={isSubmitting}
                    classes={{ root: classes.button }}
                  >
                    {t('Cancel')}
                  </Button>
                  <Button
                    color="primary"
                    onClick={submitForm}
                    disabled={isSubmitting}
                    classes={{ root: classes.button }}
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
    }
  `,
});

export default compose(inject18n, withStyles(styles))(FileManagerFragment);
