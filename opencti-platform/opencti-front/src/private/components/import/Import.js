import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, join } from 'ramda';
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
import FileUploader from '../common/files/FileUploader';
import inject18n from '../../../components/i18n';
import FileLine from '../common/files/FileLine';
import { scopesConn } from '../common/files/FileManager';
import { FIVE_SECONDS } from '../../../utils/Time';

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

class ImportComponent extends Component {
  componentDidMount() {
    this.subscription = interval$.subscribe(() => {
      this.props.relay.refetch();
    });
  }

  componentWillUnmount() {
    this.subscription.unsubscribe();
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
    const { edges } = importFiles;
    const importConnsPerFormat = scopesConn(connectorsImport);

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
              <Paper
                classes={{ root: classes.paper }}
                elevation={2}
              >
                {edges.length ? (
                  <List>
                    {edges.map((file) => (
                      <FileLine
                        key={file.node.id}
                        file={file.node}
                        connectors={
                          importConnsPerFormat[file.node.metaData.mimetype]
                        }
                      />
                    ))}
                  </List>
                ) : (
                  <div style={{ padding: 10 }}>{t('No file for the moment')}</div>
                )}
              </Paper>
            </div>
          </Grid>
          <Grid item={true} xs={4}>
            <Typography variant="h4" gutterBottom={true}>
              {t('Enabled import connectors')}
            </Typography>
            <Paper classes={{ root: classes.paper }} elevation={2} style={{ marginTop: 15 }}>
              {connectorsImport.length ? (
                <List>
                  {connectorsImport.map((connector) => (
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
                        secondary={join(',', connector.connector_scope)}
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
        connector_scope
        updated_at
      }
    `,
  },
  ImportQuery,
);

export default compose(
  inject18n,
  withStyles(styles),
)(Import);
