import React, { useState } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import {
  compose, flatten, map, head, uniq, filter, includes, zip, fromPairs, toPairs, last,
} from 'ramda';
import Grid from '@material-ui/core/Grid';
import Typography from '@material-ui/core/Typography';
import Paper from '@material-ui/core/Paper';
import { withStyles } from '@material-ui/core';
import IconButton from '@material-ui/core/IconButton';
import { DonutSmall, DonutLarge, Usb } from '@material-ui/icons';
import { ConnectionHandler } from 'relay-runtime';
import Tooltip from '@material-ui/core/Tooltip';
import MenuItem from '@material-ui/core/MenuItem';
import Select from '@material-ui/core/Select';
import Badge from '@material-ui/core/Badge';
import { createFragmentContainer } from 'react-relay';
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
  id, entity, t, classes, connectorsExport, connectorsImport,
}) => {
  const exportScopes = uniq(flatten(map(c => c.connector_scope, connectorsExport)));
  const exportConnsPerFormat = scopesConn(connectorsExport);
  const importConnsPerFormat = scopesConn(connectorsImport);
  const [format, setFormat] = useState(head(exportScopes));
  const exportConnsTooltip = () => {
    const data = map(x => (`${x.data.name} (${x.data.active ? 'active)' : 'disconnected)'}`), exportConnsPerFormat[format]);
    return data.join(', ');
  };
  const importConnsTooltip = () => {
    const connsPair = toPairs(importConnsPerFormat);
    const data = map((x) => {
      const associateConnectors = map(s => `${s.data.name} ${s.data.active ? '(active)' : '(disconnected)'}`, last(x));
      return `${head(x)} [ ${associateConnectors.join(', ')} ]`;
    }, connsPair);
    return data.join('\r\n');
  };
  const isExportActive = () => filter(x => x.data.active, exportConnsPerFormat[format]).length > 0;
  const isImportActive = () => filter(x => x.active, connectorsImport).length > 0;
  const askExport = (exportType) => {
    commitMutation({
      mutation: FileManagerExportMutation,
      variables: { id, format, exportType },
      updater: (store) => {
        const root = store.getRootField('stixDomainEntityEdit');
        const payloads = root.getLinkedRecords('askExport', { format, exportType });
        const entityPage = store.get(id);
        const conn = ConnectionHandler.getConnection(entityPage, 'Pagination_exportFiles');
        for (let index = 0; index < payloads.length; index += 1) {
          const payload = payloads[index];
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
                        <Tooltip title={importConnsTooltip()} aria-label={importConnsTooltip()}>
                            <Badge color={isImportActive() ? 'primary' : 'secondary'}
                                   badgeContent={toPairs(importConnsPerFormat).length}
                                   anchorOrigin={{ horizontal: 'right', vertical: 'top' }}
                                   style={{ marginRight: 15 }}>
                                <Usb/>
                            </Badge>
                        </Tooltip>
                        <FileUploader entityId={id}/>
                    </div>
                    <div className="clearfix" />
                </div>
                <Paper classes={{ root: classes.paper }} elevation={2}>
                    <FileImportViewer entity={entity} connectors={importConnsPerFormat} />
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
                        <Tooltip title={exportConnsTooltip()} aria-label={exportConnsTooltip()}>
                            <Badge color={isExportActive() ? 'primary' : 'secondary'}
                                badgeContent={exportConnsPerFormat[format].length}
                                anchorOrigin={{ horizontal: 'right', vertical: 'top' }}
                                style={{ marginRight: 15 }}>
                                <Select value={format} onChange={e => setFormat(e.target.value)}>
                                    {exportScopes.map((value, i) => <MenuItem key={i} value={value}>
                                        {value}</MenuItem>)}
                                </Select>
                            </Badge>
                        </Tooltip>
                        <Tooltip title="Simple export" aria-label="Simple export">
                            <IconButton disabled={!isExportActive()} onClick={exportPartial} aria-haspopup="true" color="primary">
                                <DonutLarge/>
                            </IconButton>
                        </Tooltip>
                        <Tooltip title="Complete export" aria-label="Complete export">
                            <IconButton disabled={!isExportActive()} onClick={exportComplete} aria-haspopup="true" color="primary">
                                <DonutSmall/>
                            </IconButton>
                        </Tooltip>
                    </React.Fragment> : <span>No exporter available</span> }
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

export default compose(
  inject18n,
  withStyles(styles),
)(FileManagerFragment);
