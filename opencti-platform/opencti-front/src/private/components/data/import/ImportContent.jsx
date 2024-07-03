import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { createRefetchContainer, graphql } from 'react-relay';
import { interval } from 'rxjs';
import withStyles from '@mui/styles/withStyles';
import Typography from '@mui/material/Typography';
import List from '@mui/material/List';
import Paper from '@mui/material/Paper';
import Grid from '@mui/material/Grid';
import { Link } from 'react-router-dom';
import { Add, ArrowDropDown, ArrowDropUp, Extension } from '@mui/icons-material';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItem from '@mui/material/ListItem';
import Tooltip from '@mui/material/Tooltip';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import { Field, Form, Formik } from 'formik';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import MenuItem from '@mui/material/MenuItem';
import DialogActions from '@mui/material/DialogActions';
import { ListItemButton } from '@mui/material';
import Button from '@mui/material/Button';
import * as Yup from 'yup';
import Fab from '@mui/material/Fab';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import SelectField from '../../../../components/fields/SelectField';
import { FIVE_SECONDS } from '../../../../utils/Time';
import { fileManagerAskJobImportMutation, scopesConn } from '../../common/files/FileManager';
import FileLine from '../../common/files/FileLine';
import inject18n from '../../../../components/i18n';
import FileUploader from '../../common/files/FileUploader';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';
import WorkbenchFileLine from '../../common/files/workbench/WorkbenchFileLine';
import FreeTextUploader from '../../common/files/FreeTextUploader';
import WorkbenchFileCreator from '../../common/files/workbench/WorkbenchFileCreator';
import ManageImportConnectorMessage from './ManageImportConnectorMessage';
import { truncate } from '../../../../utils/String';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import withRouter from '../../../../utils/compat-router/withRouter';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { resolveHasUserChoiceParsedCsvMapper } from '../../../../utils/csvMapperUtils';

const interval$ = interval(FIVE_SECONDS);

const styles = (theme) => ({
  container: {
    margin: 0,
  },
  title: {
    float: 'left',
    textTransform: 'uppercase',
  },
  gridContainer: {
    marginBottom: 20,
  },
  paper: {
    height: '100%',
    minHeight: '100%',
    padding: '10px 15px 10px 15px',
    borderRadius: 4,
    marginTop: 2,
  },
  item: {
    paddingLeft: 10,
    height: 50,
  },
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
  linesContainer: {
    marginTop: 10,
  },
  itemHead: {
    paddingLeft: 10,
    textTransform: 'uppercase',
  },
  bodyItem: {
    height: '100%',
    fontSize: 13,
  },
  itemIcon: {
    color: theme.palette.primary.main,
  },
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
  },
});

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
    width: '20%',
    fontSize: 12,
    fontWeight: '700',
  },
  lastModified: {
    float: 'left',
    width: '20%',
    fontSize: 12,
    fontWeight: '700',
  },
};

export const importContentQuery = graphql`
  query ImportContentQuery {
    connectorsForImport {
      ...ImportContent_connectorsImport
    }
    importFiles(first: 500) @connection(key: "Pagination_global_importFiles") {
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
    pendingFiles(first: 500)
      @connection(key: "Pagination_global_pendingFiles") {
      edges {
        node {
          id
          ...WorkbenchFileLine_file
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

class ImportContentComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      fileToImport: null,
      fileToValidate: null,
      displayCreate: false,
      sortBy: 'name',
      orderAsc: true,
      selectedConnector: null,
      hasUserChoiceCsvMapper: false,
    };
  }

  componentDidMount() {
    this.subscription = interval$.subscribe(() => {
      this.props.relay.refetch();
    });
  }

  componentWillUnmount() {
    this.subscription.unsubscribe();
  }

  handleSetCsvMapper(_, csvMapper) {
    const parsedCsvMapper = JSON.parse(csvMapper);
    const parsedRepresentations = JSON.parse(parsedCsvMapper.representations);
    const selectedCsvMapper = {
      ...parsedCsvMapper,
      representations: [...parsedRepresentations],
    };
    this.setState({ hasUserChoiceCsvMapper: resolveHasUserChoiceParsedCsvMapper(selectedCsvMapper) });
  }

  handleOpenImport(file) {
    this.setState({ fileToImport: file });
  }

  handleCloseImport() {
    this.setState({
      fileToImport: null,
    });
  }

  handleOpenValidate(file) {
    this.setState({ fileToValidate: file });
  }

  handleCloseValidate() {
    this.setState({ fileToValidate: null });
  }

  handleOpenCreate() {
    this.setState({ displayCreate: true });
  }

  handleCloseCreate() {
    this.setState({ displayCreate: false });
  }

  onSubmitImport(values, { setSubmitting, resetForm }) {
    const { connector_id, configuration, objectMarking } = values;
    let config = configuration;
    // Dynamically inject the markings chosen by the user into the csv mapper.
    const isCsvConnector = this.state.selectedConnector?.name === 'ImportCsv';
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
        fileName: this.state.fileToImport.id,
        connectorId: connector_id,
        configuration: config,
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        this.handleCloseImport();
        MESSAGING$.notifySuccess(this.props.t('Import successfully asked'));
      },
    });
  }

  onSubmitValidate(values, { setSubmitting, resetForm }) {
    commitMutation({
      mutation: fileManagerAskJobImportMutation,
      variables: {
        fileName: this.state.fileToValidate.id,
        connectorId: values.connector_id,
        bypassValidation: true,
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        this.handleCloseValidate();
        MESSAGING$.notifySuccess(this.props.t('Import successfully asked'));
      },
    });
  }

  onCreateWorkbenchCompleted() {
    this.props.relay.refetch();
  }

  reverseBy(field) {
    this.setState({ sortBy: field, orderAsc: !this.state.orderAsc });
  }

  SortHeader(field, label, isSortable) {
    const { t } = this.props;
    const sortComponent = this.state.orderAsc ? (
      <ArrowDropDown style={inlineStylesHeaders.iconSort} />
    ) : (
      <ArrowDropUp style={inlineStylesHeaders.iconSort} />
    );
    if (isSortable) {
      return (
        <div
          style={inlineStylesHeaders[field]}
          onClick={this.reverseBy.bind(this, field)}
        >
          <span>{t(label)}</span>
          {this.state.sortBy === field ? sortComponent : ''}
        </div>
      );
    }
    return (
      <div style={inlineStylesHeaders[field]}>
        <span>{t(label)}</span>
      </div>
    );
  }

  render() {
    const {
      classes,
      t,
      importFiles,
      pendingFiles,
      nsdt,
      connectorsImport,
      relay,
    } = this.props;
    const { edges: importFilesEdges } = importFiles;
    const { edges: pendingFilesEdges } = pendingFiles;
    const { fileToImport, fileToValidate, displayCreate } = this.state;
    const connectors = connectorsImport.filter((n) => !n.only_contextual); // Can be null but not empty
    const importConnsPerFormat = scopesConn(connectors);
    const handleSelectConnector = (_, value) => {
      const selectedConnector = connectors.find((c) => c.id === value);
      this.setState({ selectedConnector });
    };
    const invalidCsvMapper = this.state.selectedConnector?.name === 'ImportCsv'
        && this.state.selectedConnector?.configurations?.length === 0;
    return (
      <>
        <Breadcrumbs variant="list" elements={[{ label: t('Data') }, { label: t('Import'), current: true }]} />
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
          style={{ marginTop: 0 }}
        >
          <Grid item={true} xs={8} style={{ paddingTop: 0 }}>
            <div style={{ height: '100%' }} className="break">
              <Typography
                variant="h4"
                gutterBottom={true}
                style={{ float: 'left' }}
              >
                {t('Uploaded files')}
              </Typography>
              <div style={{ float: 'left', marginTop: -15 }}>
                <FileUploader
                  onUploadSuccess={() => relay.refetch()}
                  size="medium"
                />
                <FreeTextUploader
                  onUploadSuccess={() => relay.refetch()}
                  size="medium"
                />
              </div>
              <div className="clearfix" />
              <Paper classes={{ root: classes.paper }} variant="outlined">
                {importFilesEdges.length ? (
                  <List>
                    {importFilesEdges.map((file) => file?.node && (
                      <FileLine
                        key={file.node.id}
                        file={file.node}
                        connectors={
                          importConnsPerFormat[file.node.metaData.mimetype]
                        }
                        handleOpenImport={this.handleOpenImport.bind(this)}
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
                      {t('No file for the moment')}
                    </span>
                  </div>
                )}
              </Paper>
            </div>
          </Grid>
          <Grid item={true} xs={4} style={{ paddingTop: 0 }}>
            <Typography variant="h4" gutterBottom={true}>
              {t('Enabled import connectors')}
            </Typography>
            <Paper
              classes={{ root: classes.paper }}
              variant="outlined"
              style={{ marginTop: 12 }}
            >
              {connectors.length ? (
                <List>
                  {connectors.map((connector) => {
                    const connectorScope = connector.connector_scope.join(',');
                    return (
                      <ListItemButton
                        component={Link}
                        to={`/dashboard/data/ingestion/connectors/${connector.id}`}
                        key={connector.id}
                        dense={true}
                        divider={true}
                        classes={{ root: classes.item }}
                      >
                        <Tooltip
                          title={
                            connector.active
                              ? t('This connector is active')
                              : t('This connector is disconnected')
                          }
                        >
                          <ListItemIcon
                            style={{
                              color: connector.active ? '#4caf50' : '#f44336',
                            }}
                          >
                            <Extension/>
                          </ListItemIcon>
                        </Tooltip>
                        <Tooltip title={connectorScope}>
                          <ListItemText
                            primary={connector.name}
                            secondary={truncate(connectorScope, 30)}
                          />
                        </Tooltip>
                        {connector.updated_at && (<ListItemSecondaryAction>
                          <ListItemText primary={nsdt(connector.updated_at)}/>
                        </ListItemSecondaryAction>)}
                      </ListItemButton>
                    );
                  })}
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
                    {t('No enrichment connectors on this platform')}
                  </span>
                </div>
              )}
            </Paper>
          </Grid>
          <Grid item={true} xs={12} style={{ marginTop: 40 }}>
            <div style={{ height: '100%' }} className="break">
              <Typography
                variant="h4"
                gutterBottom={true}
                style={{ marginBottom: 15 }}
              >
                {t('Analyst workbenches')}
              </Typography>
              <Paper classes={{ root: classes.paper }} variant="outlined">
                <List>
                  <ListItem
                    classes={{ root: classes.itemHead }}
                    divider={false}
                    style={{ paddingTop: 0 }}
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
                          {this.SortHeader('name', 'Name', false)}
                          {this.SortHeader('creator_name', 'Creator', false)}
                          {this.SortHeader('labels', 'Labels', false)}
                          {this.SortHeader(
                            'lastModified',
                            'Modification date',
                            false,
                          )}
                        </div>
                      }
                    />
                    <ListItemSecondaryAction style={{ width: 96 }}> &nbsp; </ListItemSecondaryAction>
                  </ListItem>
                  {pendingFilesEdges.map((file) => (
                    <WorkbenchFileLine
                      key={file.node.id}
                      file={file.node}
                      connectors={
                        importConnsPerFormat[file.node.metaData.mimetype]
                      }
                      handleOpenImport={this.handleOpenValidate.bind(this)}
                    />
                  ))}
                </List>
              </Paper>
            </div>
          </Grid>
        </Grid>
        <div>
          <Formik
            enableReinitialize={true}
            initialValues={{ connector_id: '', configuration: '', objectMarking: [] }}
            validationSchema={importValidation(t, !!this.state.selectedConnector?.configurations)}
            onSubmit={this.onSubmitImport.bind(this)}
            onReset={this.handleCloseImport.bind(this)}
          >
            {({ submitForm, handleReset, isSubmitting, setFieldValue, isValid }) => (
              <Form style={{ margin: '0 0 20px 0' }}>
                <Dialog
                  open={fileToImport}
                  PaperProps={{ elevation: 1 }}
                  keepMounted={true}
                  onClose={() => handleReset()}
                  fullWidth={true}
                >
                  <DialogTitle>{`${t('Launch an import')}`}</DialogTitle>
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
                      {connectors.map((connector) => {
                        const disabled = !fileToImport
                          || (connector.connector_scope.length > 0
                            && !R.includes(
                              fileToImport.metaData.mimetype,
                              connector.connector_scope,
                            ));
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
                    {this.state.selectedConnector?.configurations?.length > 0
                      ? <Field
                          component={SelectField}
                          variant="standard"
                          name="configuration"
                          label={t('Configuration')}
                          fullWidth={true}
                          containerstyle={{ marginTop: 20, width: '100%' }}
                          onChange={this.handleSetCsvMapper.bind(this)}
                        >
                        {this.state.selectedConnector.configurations?.map((config) => {
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
                      : <ManageImportConnectorMessage name={this.state.selectedConnector?.name }/>
                    }
                    {this.state.selectedConnector?.name === 'ImportCsv'
                      && this.state.hasUserChoiceCsvMapper
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
                      {t('Cancel')}
                    </Button>
                    <Button
                      color="secondary"
                      onClick={submitForm}
                      disabled={isSubmitting || !isValid || invalidCsvMapper || !this.state.selectedConnector}
                    >
                      {t('Create')}
                    </Button>
                  </DialogActions>
                </Dialog>
              </Form>
            )}
          </Formik>
          <Formik
            enableReinitialize={true}
            initialValues={{ connector_id: '' }}
            validationSchema={importValidation(t)}
            onSubmit={this.onSubmitValidate.bind(this)}
            onReset={this.handleCloseValidate.bind(this)}
          >
            {({ submitForm, handleReset, isSubmitting }) => (
              <Form style={{ margin: '0 0 20px 0' }}>
                <Dialog
                  open={fileToValidate}
                  PaperProps={{ elevation: 1 }}
                  keepMounted={true}
                  onClose={this.handleCloseValidate.bind(this)}
                  fullWidth={true}
                >
                  <DialogTitle>{t('Validate and send for import')}</DialogTitle>
                  <DialogContent>
                    <Field
                      component={SelectField}
                      variant="standard"
                      name="connector_id"
                      label={t('Connector')}
                      fullWidth={true}
                      containerstyle={{ width: '100%' }}
                    >
                      {connectors.map((connector, i) => {
                        const disabled = !fileToValidate
                          || (connector.connector_scope.length > 0
                            && !R.includes(
                              fileToValidate.metaData.mimetype,
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
          <WorkbenchFileCreator
            handleCloseCreate={this.handleCloseCreate.bind(this)}
            openCreate={displayCreate}
            onCompleted={this.onCreateWorkbenchCompleted.bind(this)}
          />
        </div>
        <Fab
          onClick={this.handleOpenCreate.bind(this)}
          color="primary"
          aria-label="Add"
          className={classes.createButton}
        >
          <Add />
        </Fab>
      </>
    );
  }
}

ImportContentComponent.propTypes = {
  connectorsImport: PropTypes.array,
  importFiles: PropTypes.object,
  pendingFiles: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  nsdt: PropTypes.func,
};

const ImportContent = createRefetchContainer(
  ImportContentComponent,
  {
    connectorsImport: graphql`
      fragment ImportContent_connectorsImport on Connector
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
    `,
  },
  importContentQuery,
);

export default R.compose(inject18n, withStyles(styles), withRouter)(ImportContent);
