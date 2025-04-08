import React, { useEffect, useState } from 'react';
import { createRefetchContainer, graphql } from 'react-relay';
import { interval } from 'rxjs';
import Typography from '@mui/material/Typography';
import List from '@mui/material/List';
import Paper from '@mui/material/Paper';
import Grid from '@mui/material/Grid';
import { Add, ArrowDropDown, ArrowDropUp } from '@mui/icons-material';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItem from '@mui/material/ListItem';
import { Field, Form, Formik } from 'formik';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import MenuItem from '@mui/material/MenuItem';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import * as Yup from 'yup';
import Fab from '@mui/material/Fab';
import makeStyles from '@mui/styles/makeStyles';
import ImportMenu from '../ImportMenu';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import SelectField from '../../../../components/fields/SelectField';
import { TEN_SECONDS } from '../../../../utils/Time';
import { fileManagerAskJobImportMutation, scopesConn } from '../../common/files/FileManager';
import FileLine from '../../common/files/FileLine';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';
import WorkbenchFileLine from '../../common/files/workbench/WorkbenchFileLine';
import WorkbenchFileCreator from '../../common/files/workbench/WorkbenchFileCreator';
import ManageImportConnectorMessage from './ManageImportConnectorMessage';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { resolveHasUserChoiceParsedCsvMapper } from '../../../../utils/csvMapperUtils';
import useConnectedDocumentModifier from '../../../../utils/hooks/useConnectedDocumentModifier';
import useDraftContext from '../../../../utils/hooks/useDraftContext';
import UploadImport from '../../../../components/UploadImport';

const interval$ = interval(TEN_SECONDS);

const useStyles = makeStyles(() => ({
  gridContainer: {
    marginBottom: 20,
  },
  paper: {
    padding: '10px 15px 10px 15px',
    borderRadius: 4,
    marginTop: 2,
  },
  itemHead: {
    paddingLeft: 10,
    textTransform: 'uppercase',
  },
  createButton: {
    position: 'fixed',
    bottom: 30,
  },
}));

const inlineStylesHeaders = {
  iconSort: {
    position: 'absolute',
    margin: '0 0 0 5px',
    padding: 0,
    top: '0px',
  },
  name: {
    float: 'left',
    width: '35%',
    fontSize: 12,
    fontWeight: '700',
  },
  creator_name: {
    float: 'left',
    width: '20%',
    fontSize: 12,
    fontWeight: '700',
  },
  labels: {
    float: 'left',
    width: '15%',
    fontSize: 12,
    fontWeight: '700',
  },
  markings: {
    float: 'left',
    width: '15%',
    fontSize: 12,
    fontWeight: '700',
  },
  lastModified: {
    float: 'left',
    width: '10%',
    fontSize: 12,
    fontWeight: '700',
  },
};

const importConnectorsFragment = graphql`
  fragment ImportContentContainer_connectorsImport on Connector
  @relay(plural: true) {
    id
    name
    active
    only_contextual
    connector_scope
    updated_at
    configurations {
      id
      name,
      configuration
    }
  }
`;

export const importContentQuery = graphql`
  query ImportContentQuery {
    connectorsForImport {
        ...ImportContentContainer_connectorsImport
    }
    importFiles(first: 100) @connection(key: "Pagination_global_importFiles") {
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
    pendingFiles(first: 100) @connection(key: "Pagination_global_pendingFiles") {
      edges {
        node {
          id
          ...ImportWorkbenchesContentFileLine_file
          metaData {
            mimetype
          }
        }
      }
    }
  }
`;

const importValidation = (t, configurations) => {
  const shape = {
    connector_id: Yup.string().required(t('This field is required')),
  };
  if (configurations) {
    return Yup.object().shape({
      ...shape,
      configuration: Yup.string().required(t('This field is required')),
    });
  }
  return Yup.object().shape(shape);
};

const ImportContentComponent = ({
  connectorsImport,
  relay,
  importFiles,
  pendingFiles,
  isNewImportScreensEnabled,
  inDraftOverview,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  const draftContext = useDraftContext();
  setTitle(t_i18n('Import | Import | Data'));

  const [fileToImport, setFileToImport] = useState(null);
  const [fileToValidate, setFileToValidate] = useState(null);
  const [displayCreate, setDisplayCreate] = useState(false);
  const [sortBy, setSortBy] = useState('name');
  const [orderAsc, setOrderAsc] = useState(true);
  const [selectedConnector, setSelectedConnector] = useState(null);
  const [hasUserChoiceCsvMapper, setHasUserChoiceCsvMapper] = useState(false);

  useEffect(() => {
    const subscription = interval$.subscribe(() => {
      relay.refetch();
    });
    return () => {
      subscription.unsubscribe();
    };
  }, []);

  const handleSetCsvMapper = (_, csvMapper) => {
    const parsedCsvMapper = JSON.parse(csvMapper);
    const parsedRepresentations = JSON.parse(parsedCsvMapper.representations);
    const selectedCsvMapper = {
      ...parsedCsvMapper,
      representations: [...parsedRepresentations],
    };
    setHasUserChoiceCsvMapper(resolveHasUserChoiceParsedCsvMapper(selectedCsvMapper));
  };

  const handleOpenImport = (file) => {
    setFileToImport(file);
  };
  const handleCloseImport = () => {
    setFileToImport(null);
  };

  const handleOpenValidate = (file) => {
    setFileToValidate(file);
  };
  const handleCloseValidate = () => {
    setFileToValidate(null);
  };

  const handleOpenCreate = () => {
    setDisplayCreate(true);
  };
  const handleCloseCreate = () => {
    setDisplayCreate(false);
  };

  const onSubmitImport = (values, { setSubmitting, resetForm }) => {
    const { connector_id, configuration, objectMarking, validation_mode } = values;
    let config = configuration;
    // Dynamically inject the markings chosen by the user into the csv mapper.
    const isCsvConnector = selectedConnector?.name === 'ImportCsv';
    if (isCsvConnector && configuration && objectMarking) {
      const parsedConfig = JSON.parse(configuration);
      if (typeof parsedConfig === 'object') {
        parsedConfig.markings = objectMarking.map((marking) => marking.value);
        config = JSON.stringify(parsedConfig);
      }
    }
    commitMutation({
      mutation: fileManagerAskJobImportMutation,
      variables: {
        fileName: fileToImport.id,
        connectorId: connector_id,
        configuration: config,
        validationMode: validation_mode,
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        handleCloseImport();
        MESSAGING$.notifySuccess(t_i18n('Import successfully asked'));
      },
    });
  };

  const onSubmitValidate = (values, { setSubmitting, resetForm }) => {
    commitMutation({
      mutation: fileManagerAskJobImportMutation,
      variables: {
        fileName: fileToValidate.id,
        connectorId: values.connector_id,
        bypassValidation: true,
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        handleCloseValidate();
        MESSAGING$.notifySuccess(t_i18n('Import successfully asked'));
      },
    });
  };

  const onCreateWorkbenchCompleted = () => {
    relay.refetch();
  };

  const reverseBy = (field) => {
    setSortBy(field);
    setOrderAsc(!orderAsc);
  };

  const sortHeader = (field, label, isSortable) => {
    const sortComponent = orderAsc ? (
      <ArrowDropDown style={inlineStylesHeaders.iconSort} />
    ) : (
      <ArrowDropUp style={inlineStylesHeaders.iconSort} />
    );
    if (isSortable) {
      return (
        <div
          style={inlineStylesHeaders[field]}
          onClick={() => reverseBy(field)}
        >
          <span>{t_i18n(label)}</span>
          {sortBy === field ? sortComponent : ''}
        </div>
      );
    }
    return (
      <div style={inlineStylesHeaders[field]}>
        <span>{t_i18n(label)}</span>
      </div>
    );
  };

  const { edges: importFilesEdges } = importFiles;
  const { edges: pendingFilesEdges } = pendingFiles;
  const connectors = connectorsImport.filter((n) => !n.only_contextual); // Can be null but not empty
  const importConnsPerFormat = scopesConn(connectors);
  const handleSelectConnector = (_, value) => {
    const connector = connectors.find((c) => c.id === value);
    setSelectedConnector(connector);
  };

  const invalidCsvMapper = selectedConnector?.name === 'ImportCsv' && selectedConnector?.configurations?.length === 0;
  return (
    <div style={{ paddingRight: isNewImportScreensEnabled && !inDraftOverview ? 200 : 0 }}>
      {!inDraftOverview && (
      <Breadcrumbs
        elements={[{ label: t_i18n('Data') }, { label: t_i18n('Import'), current: true }]}
      />
      )}
      {isNewImportScreensEnabled && !inDraftOverview && <ImportMenu/>}
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
        style={{ marginTop: 0 }}
      >
        <Grid item xs={12} style={{ paddingTop: 0 }}>
          <div style={{ height: '100%' }} className="break">
            <Typography
              variant="h4"
              gutterBottom={true}
              style={{ float: 'left' }}
            >
              {t_i18n('Uploaded files')}
            </Typography>
            <div style={{ float: 'left', marginTop: -15 }}>
              <UploadImport
                onUploadSuccess={() => relay.refetch()}
              />
            </div>
            <div className="clearfix" />
            <Paper classes={{ root: classes.paper }} className={'paper-for-grid'} variant="outlined">
              {importFilesEdges.length ? (
                <List>
                  {importFilesEdges.map((file) => file?.node && (
                  <FileLine
                    key={file.node.id}
                    file={file.node}
                    connectors={ importConnsPerFormat[file.node.metaData.mimetype] }
                    handleOpenImport={handleOpenImport}
                  />
                  ))}
                </List>
              ) : (
                <div
                  style={{ display: 'table', height: '100%', width: '100%' }}
                >
                  <span
                    style={{
                      display: 'table-cell',
                      verticalAlign: 'middle',
                      textAlign: 'center',
                    }}
                  >
                    {t_i18n('No file for the moment')}
                  </span>
                </div>
              )}
            </Paper>
          </div>
        </Grid>
        {!inDraftOverview && (<Grid item xs={12}>
          <div style={{ height: '100%' }} className="break">
            <Typography
              variant="h4"
              gutterBottom={true}
              style={{ marginBottom: 15 }}
            >
              {t_i18n('Analyst workbenches')}
            </Typography>
            <Paper classes={{ root: classes.paper }} variant="outlined">
              <List>
                <ListItem
                  classes={{ root: classes.itemHead }}
                  divider={false}
                  style={{ paddingTop: 0 }}
                  secondaryAction={
                    <div style={{ width: 96 }}> &nbsp; </div>
                  }
                >
                  <ListItemIcon>
                    <span
                      style={{
                        padding: '0 8px 0 8px',
                        fontWeight: 700,
                        fontSize: 12,
                      }}
                    >
                        &nbsp;
                    </span>
                  </ListItemIcon>
                  <ListItemText
                    primary={
                      <div>
                        {sortHeader('name', 'Name', false)}
                        {sortHeader('creator_name', 'Creator', false)}
                        {sortHeader('labels', 'Labels', false)}
                        {sortHeader('markings', 'Markings', false)}
                        {sortHeader('lastModified', 'Modification date', false)}
                      </div>
                      }
                  />
                </ListItem>
                {pendingFilesEdges.map((file) => (
                  <WorkbenchFileLine
                    key={file.node.id}
                    file={file.node}
                    connectors={importConnsPerFormat[file.node.metaData.mimetype]}
                    handleOpenImport={handleOpenValidate}
                  />
                ))}
              </List>
            </Paper>
          </div>
        </Grid>)}
      </Grid>
      <div>
        <Formik
          enableReinitialize={true}
          initialValues={{ connector_id: '', validation_mode: draftContext ? 'draft' : 'workbench', configuration: '', objectMarking: [] }}
          validationSchema={importValidation(t_i18n, !!selectedConnector?.configurations)}
          onSubmit={onSubmitImport}
          onReset={handleCloseImport}
        >
          {({ submitForm, handleReset, isSubmitting, setFieldValue, isValid }) => (
            <Form style={{ margin: '0 0 20px 0' }}>
              <Dialog
                open={!!fileToImport}
                slotProps={{ paper: { elevation: 1 } }}
                keepMounted={true}
                onClose={() => handleReset()}
                fullWidth={true}
              >
                <DialogTitle>{`${t_i18n('Launch an import')}`}</DialogTitle>
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
                    {connectors.map((connector) => {
                      const disabled = !fileToImport
                          || (connector.connector_scope.length > 0
                            && !connector.connector_scope.includes(fileToImport.metaData.mimetype));
                      return (
                        <MenuItem
                          key={connector.id}
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
                        key={'workbench'}
                        value={'workbench'}
                      >
                        {'Workbench'}
                      </MenuItem>
                      <MenuItem
                        key={'draft'}
                        value={'draft'}
                      >
                        {'Draft'}
                      </MenuItem>
                    </Field>
                  )}
                  {selectedConnector?.configurations?.length > 0
                    ? <Field
                        component={SelectField}
                        variant="standard"
                        name="configuration"
                        label={t_i18n('Configuration')}
                        fullWidth={true}
                        containerstyle={{ marginTop: 20, width: '100%' }}
                        onChange={handleSetCsvMapper}
                      >
                      {selectedConnector.configurations?.map((config) => {
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
                    : <ManageImportConnectorMessage name={selectedConnector?.name }/>
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
        <Formik
          enableReinitialize={true}
          initialValues={{ connector_id: '' }}
          validationSchema={importValidation(t_i18n)}
          onSubmit={onSubmitValidate}
          onReset={handleCloseValidate}
        >
          {({ submitForm, handleReset, isSubmitting }) => (
            <Form style={{ margin: '0 0 20px 0' }}>
              <Dialog
                open={!!fileToValidate}
                slotProps={{ paper: { elevation: 1 } }}
                keepMounted={true}
                onClose={handleCloseValidate}
                fullWidth={true}
              >
                <DialogTitle>{t_i18n('Validate and send for import')}</DialogTitle>
                <DialogContent>
                  <Field
                    component={SelectField}
                    variant="standard"
                    name="connector_id"
                    label={t_i18n('Connector')}
                    fullWidth={true}
                    containerstyle={{ width: '100%' }}
                  >
                    {connectors.map((connector, i) => {
                      const disabled = !fileToValidate
                        || (connector.connector_scope.length > 0
                          && !connector.connector_scope.includes(fileToValidate.metaData.mimetype));
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
                    {t_i18n('Cancel')}
                  </Button>
                  <Button
                    color="secondary"
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
        {!inDraftOverview && (
        <WorkbenchFileCreator
          handleCloseCreate={handleCloseCreate}
          openCreate={displayCreate}
          onCompleted={onCreateWorkbenchCompleted}
        />
        )}
      </div>
      {!inDraftOverview && (
      <Fab
        onClick={handleOpenCreate}
        color="primary"
        aria-label="Add"
        className={classes.createButton}
        style={{ right: isNewImportScreensEnabled ? 230 : 30 }}
      >
        <Add />
      </Fab>
      )}
    </div>
  );
};

const ImportContent = createRefetchContainer(
  ImportContentComponent,
  {
    connectorsImport: importConnectorsFragment,
  },
  importContentQuery,
);

export default ImportContent;
