import React, { useState } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import {
  compose, flatten, map, head, uniq, filter, includes, zip, fromPairs,
} from 'ramda';
import Grid from '@material-ui/core/Grid';
import Typography from '@material-ui/core/Typography';
import Paper from '@material-ui/core/Paper';
import { withStyles } from '@material-ui/core';
import IconButton from '@material-ui/core/IconButton';
import { DonutSmall, DonutLarge } from '@material-ui/icons';
import { ConnectionHandler } from 'relay-runtime';
import Tooltip from '@material-ui/core/Tooltip';
import MenuItem from '@material-ui/core/MenuItem';
import Select from '@material-ui/core/Select';
import Badge from '@material-ui/core/Badge';
import inject18n from '../../../../components/i18n';
import FileUploader from './FileUploader';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';
import FileImportViewer from './FileImportViewer';
import FileExportViewer from './FileExportViewer';

const styles = () => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
  paper: {
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
});

export const FileManagerExportMutation = graphql`
    mutation FileManagerExportMutation($id: ID!, $format: String!, $exportType: String!) {
        stixDomainEntityEdit(id: $id) {
            askExport(format: $format, exportType: $exportType) {
                id
                name
                uploadStatus
                lastModifiedSinceMin
            }
        }
    }
`;

const scopesConn = (exportConnectors) => {
  const scopes = uniq(flatten(map(c => c.connector_scope, exportConnectors)));
  const connectors = map((s) => {
    const filteredConnectors = filter(e => includes(s, e.connector_scope), exportConnectors);
    return map(x => ({ data: { name: x.name, active: x.active } }), filteredConnectors);
  }, scopes);
  const zipped = zip(scopes, connectors);
  return fromPairs(zipped);
};

const FileManager = ({
  id, entity, t, classes, exportConnectors,
}) => {
  const scopes = uniq(flatten(map(c => c.connector_scope, exportConnectors)));
  const scopesConnectors = scopesConn(exportConnectors);
  const [format, setFormat] = useState(head(scopes));
  const connsTooltip = () => {
    const data = map(x => (`${x.data.name} (${x.data.active ? 'active)' : 'disconnected)'}`), scopesConnectors[format]);
    return data.join(', ');
  };
  const isFormatActive = () => filter(x => x.data.active, scopesConnectors[format]).length > 0;
  const askExport = (exportType) => {
    commitMutation({
      mutation: FileManagerExportMutation,
      variables: { id, format, exportType },
      updater: (store) => {
        const root = store.getRootField('stixDomainEntityEdit');
        const payloads = root.getLinkedRecords('askExport', { format, exportType });
        const entityPage = store.get(id);
        const conn = ConnectionHandler.getConnection(entityPage, 'Pagination_exportFiles');
        for (const payload of payloads) {
          const newEdge = payload.setLinkedRecord(payload, 'node');
          ConnectionHandler.insertEdgeBefore(conn, newEdge);
        }
      },
      onCompleted: () => {
        MESSAGING$.notifySuccess('Export successfully started');
      },
    });
  };
  const exportPartial = () => askExport('simple');
  const exportComplete = () => askExport('full');
  return <div>
        <Grid container={true} spacing={3} classes={{ container: classes.gridContainer }}>
            <Grid item={true} xs={6}>
                <div>
                    <div style={{ float: 'left' }}>
                        <Typography variant="h2" style={{ paddingTop: 15 }} gutterBottom={true}>
                            {t('Uploaded / Imported files')}
                        </Typography>
                    </div>
                    <div style={{ float: 'right' }}>
                        <FileUploader entityId={id}/>
                    </div>
                    <div className="clearfix" />
                </div>
                <Paper classes={{ root: classes.paper }} elevation={2}>
                    <FileImportViewer entity={entity} />
                </Paper>
            </Grid>
            <Grid item={true} xs={6}>
                <div style={{ float: 'left' }}>
                    <Typography variant="h2" style={{ paddingTop: 15 }} gutterBottom={true}>
                        {t('Generated / Exported files')}
                    </Typography>
                </div>
                <div style={{ float: 'right' }}>
                    { format ? <React.Fragment>
                        <Tooltip title={connsTooltip()} aria-label={connsTooltip()}>
                            <Badge color={isFormatActive() ? 'primary' : 'secondary'}
                                badgeContent={scopesConnectors[format].length}
                                anchorOrigin={{ horizontal: 'right', vertical: 'top' }}
                                style={{ marginRight: 15 }}>
                                <Select value={format} onChange={e => setFormat(e.target.value)}>
                                    {scopes.map((value, i) => <MenuItem key={i} value={value}>
                                        {value}</MenuItem>)}
                                </Select>
                            </Badge>
                        </Tooltip>
                        <Tooltip title="Simple export" aria-label="Simple export">
                            <IconButton disabled={!isFormatActive()} onClick={exportPartial} aria-haspopup="true" color="primary">
                                <DonutLarge/>
                            </IconButton>
                        </Tooltip>
                        <Tooltip title="Complete export" aria-label="Complete export">
                            <IconButton disabled={!isFormatActive()} onClick={exportComplete} aria-haspopup="true" color="primary">
                                <DonutSmall/>
                            </IconButton>
                        </Tooltip>
                    </React.Fragment> : <span>No exporter available</span>
                    }
                </div>
                <div className="clearfix" />
                <Paper classes={{ root: classes.paper }} elevation={2}>
                    <FileExportViewer entity={entity} />
                </Paper>
            </Grid>
        </Grid>
    </div>;
};

FileManager.propTypes = {
  nsdt: PropTypes.func,
  id: PropTypes.string.isRequired,
  entity: PropTypes.object.isRequired,
  exportConnectors: PropTypes.array.isRequired,
};

export default compose(
  inject18n,
  withStyles(styles),
)(FileManager);
