import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { createRefetchContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { interval } from 'rxjs';
import { withStyles } from '@material-ui/core';
import Typography from '@material-ui/core/Typography';
import List from '@material-ui/core/List';
import Paper from '@material-ui/core/Paper';
import Grid from '@material-ui/core/Grid';
import { Extension } from '@material-ui/icons';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import ListItem from '@material-ui/core/ListItem';
import Tooltip from '@material-ui/core/Tooltip';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import { Field, Form, Formik } from 'formik';
import Dialog from '@material-ui/core/Dialog';
import DialogTitle from '@material-ui/core/DialogTitle';
import DialogContent from '@material-ui/core/DialogContent';
import MenuItem from '@material-ui/core/MenuItem';
import DialogActions from '@material-ui/core/DialogActions';
import Button from '@material-ui/core/Button';
import * as Yup from 'yup';
import SelectField from '../../../components/SelectField';
import { FIVE_SECONDS } from '../../../utils/Time';
import {
  fileManagerAskJobImportMutation,
  scopesConn,
} from '../common/files/FileManager';
import FileLine from '../common/files/FileLine';
import inject18n from '../../../components/i18n';
import FileUploader from '../common/files/FileUploader';
import { commitMutation, MESSAGING$ } from '../../../relay/environment';

const interval$ = interval(FIVE_SECONDS);

const styles = () => ({
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
    borderRadius: 6,
  },
  item: {
    paddingLeft: 10,
    height: 50,
  },
});

export const ImportQuery = graphql`
  query ImportQuery {
    connectorsForImport {
      ...Import_connectorsImport
    }
    importFiles(first: 1000) @connection(key: "Pagination_global_importFiles") {
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
`;

const importValidation = (t) => Yup.object().shape({
  connector_id: Yup.string().required(t('This field is required')),
});

class ImportComponent extends Component {
  constructor(props) {
    super(props);
    this.state = { fileToImport: null };
  }

  componentDidMount() {
    this.subscription = interval$.subscribe(() => {
      this.props.relay.refetch();
    });
  }

  componentWillUnmount() {
    this.subscription.unsubscribe();
  }

  handleOpenImport(file) {
    this.setState({ fileToImport: file });
  }

  handleCloseImport() {
    this.setState({ fileToImport: null });
  }

  onSubmitImport(values, { setSubmitting, resetForm }) {
    commitMutation({
      mutation: fileManagerAskJobImportMutation,
      variables: {
        fileName: this.state.fileToImport.id,
        connectorId: values.connector_id,
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        this.handleCloseImport();
        MESSAGING$.notifySuccess('Import successfully asked');
      },
    });
  }

  render() {
    const {
      classes,
      t,
      nsdt,
      importFiles,
      connectorsImport,
      relay,
    } = this.props;
    const { fileToImport } = this.state;
    const { edges } = importFiles;
    const connectors = R.filter((n) => !n.only_contextual, connectorsImport);
    const importConnsPerFormat = scopesConn(connectors);
    return (
      <div className={classes.container}>
        <Typography
          variant="h1"
          gutterBottom={true}
          classes={{ root: classes.title }}
        >
          {t('Data import')}
        </Typography>
        <div className="clearfix" />
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
          style={{ marginTop: 20 }}
        >
          <Grid item={true} xs={8}>
            <div style={{ height: '100%' }} className="break">
              <Typography
                variant="h4"
                gutterBottom={true}
                style={{ float: 'left' }}
              >
                {t('Uploaded files')}
              </Typography>
              <div style={{ float: 'left', marginTop: -17 }}>
                <FileUploader onUploadSuccess={() => relay.refetch()} />
              </div>
              <div className="clearfix" />
              <Paper classes={{ root: classes.paper }} elevation={2}>
                {edges.length ? (
                  <List>
                    {edges.map((file) => (
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
                  <div style={{ padding: 10 }}>
                    {t('No file for the moment')}
                  </div>
                )}
              </Paper>
            </div>
          </Grid>
          <Grid item={true} xs={4}>
            <Typography variant="h4" gutterBottom={true}>
              {t('Enabled import connectors')}
            </Typography>
            <Paper
              classes={{ root: classes.paper }}
              elevation={2}
              style={{ marginTop: 15 }}
            >
              {connectors.length ? (
                <List>
                  {connectors.map((connector) => (
                    <ListItem
                      key={connector.id}
                      dense={true}
                      divider={true}
                      classes={{ root: classes.item }}
                      button={true}
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
                          <Extension />
                        </ListItemIcon>
                      </Tooltip>
                      <ListItemText
                        primary={connector.name}
                        secondary={R.join(',', connector.connector_scope)}
                      />
                      <ListItemSecondaryAction>
                        <ListItemText primary={nsdt(connector.updated_at)} />
                      </ListItemSecondaryAction>
                    </ListItem>
                  ))}
                </List>
              ) : (
                <div style={{ padding: 10 }}>
                  {t('No enrichment connectors on this platform')}
                </div>
              )}
            </Paper>
          </Grid>
        </Grid>
        <div>
          <Formik
            enableReinitialize={true}
            initialValues={{ connector_id: '' }}
            validationSchema={importValidation(t)}
            onSubmit={this.onSubmitImport.bind(this)}
            onReset={this.handleCloseImport.bind(this)}
          >
            {({ submitForm, handleReset, isSubmitting }) => (
              <Form style={{ margin: '0 0 20px 0' }}>
                <Dialog
                  open={fileToImport}
                  keepMounted={true}
                  onClose={this.handleCloseImport.bind(this)}
                  fullWidth={true}
                >
                  <DialogTitle>{t('Launch an import')}</DialogTitle>
                  <DialogContent>
                    <Field
                      component={SelectField}
                      name="connector_id"
                      label={t('Connector')}
                      fullWidth={true}
                      containerstyle={{ width: '100%' }}
                    >
                      {connectors.map((connector, i) => {
                        const disabled = !fileToImport
                          || (connector.connector_scope.length > 0
                            && !R.includes(
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
  }
}

ImportComponent.propTypes = {
  connectorsImport: PropTypes.array,
  importFiles: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  nsdt: PropTypes.func,
};

const Import = createRefetchContainer(
  ImportComponent,
  {
    connectorsImport: graphql`
      fragment Import_connectorsImport on Connector @relay(plural: true) {
        id
        name
        active
        only_contextual
        connector_scope
        updated_at
      }
    `,
  },
  ImportQuery,
);

export default R.compose(inject18n, withStyles(styles))(Import);
