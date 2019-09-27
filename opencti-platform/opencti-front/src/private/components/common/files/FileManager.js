import React from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { compose } from 'ramda';
import Grid from '@material-ui/core/Grid';
import Typography from '@material-ui/core/Typography';
import Paper from '@material-ui/core/Paper';
import { withStyles } from '@material-ui/core';
import IconButton from '@material-ui/core/IconButton';
import { DonutSmall, DonutLarge } from '@material-ui/icons';
import { ConnectionHandler } from 'relay-runtime';
import inject18n from '../../../../components/i18n';
import FileUploader from './FileUploader';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';
import ReportHeader from '../../reports/ReportHeader';
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
    mutation FileManagerExportMutation($id: ID!, $exportType: String!) {
        stixDomainEntityEdit(id: $id) {
            askExport(exportType: $exportType) {
                ...FileLine_file
            }
        }
    }
`;

const FileManager = ({ report, t, classes }) => {
  const { id, internalId } = report;
  const askExport = (exportType) => {
    commitMutation({
      mutation: FileManagerExportMutation,
      variables: { id: internalId, exportType },
      updater: (store) => {
        const root = store.getRootField('stixDomainEntityEdit');
        const payload = root.getLinkedRecord('askExport', { exportType });
        const newEdge = payload.setLinkedRecord(payload, 'node');
        const entity = store.get(id);
        const conn = ConnectionHandler.getConnection(entity, 'Pagination_exportFiles');
        ConnectionHandler.insertEdgeBefore(conn, newEdge);
      },
      onCompleted: () => {
        MESSAGING$.notifySuccess('Export successfully started');
      },
    });
  };
  const exportPartial = () => askExport('stix2-bundle-simple');
  const exportComplete = () => askExport('stix2-bundle-full');
  return <div>
        <ReportHeader report={report} />
        <Grid container={true} spacing={3} classes={{ container: classes.gridContainer }}>
            <Grid item={true} xs={6}>
                <div>
                    <div style={{ float: 'left' }}>
                        <Typography variant="h2" style={{ paddingTop: 15 }} gutterBottom={true}>
                            {t('Uploaded / Imported files')}
                        </Typography>
                    </div>
                    <div style={{ float: 'right' }}>
                        <FileUploader entityId={internalId}/>
                    </div>
                    <div className="clearfix" />
                </div>
                <Paper classes={{ root: classes.paper }} elevation={2}>
                    <FileImportViewer entity={report} />
                </Paper>
            </Grid>
            <Grid item={true} xs={6}>
                <div style={{ float: 'left' }}>
                    <Typography variant="h2" style={{ paddingTop: 15 }} gutterBottom={true}>
                        {t('Generated / Exported files')}
                    </Typography>
                </div>
                <div style={{ float: 'right' }}>
                    <IconButton onClick={exportPartial} aria-haspopup="true" color="primary">
                        <DonutLarge/>
                    </IconButton>
                    <IconButton onClick={exportComplete} aria-haspopup="true" color="primary">
                        <DonutSmall/>
                    </IconButton>
                </div>
                <div className="clearfix" />
                <Paper classes={{ root: classes.paper }} elevation={2}>
                    <FileExportViewer entity={report} />
                </Paper>
            </Grid>
        </Grid>
    </div>;
};

FileManager.propTypes = {
  nsdt: PropTypes.func,
  report: PropTypes.object,
};

export default compose(
  inject18n,
  withStyles(styles),
)(FileManager);
