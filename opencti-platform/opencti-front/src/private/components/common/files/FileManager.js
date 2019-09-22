import React from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { compose, map } from 'ramda';
import Grid from '@material-ui/core/Grid';
import Typography from '@material-ui/core/Typography';
import Paper from '@material-ui/core/Paper';
import { withStyles } from '@material-ui/core';
import ReportHeader from '../../reports/ReportHeader';
import { QueryRenderer } from '../../../../relay/environment';
import FileViewer from './FileViewer';
import FileUploader from './FileUploader';
import inject18n from '../../../../components/i18n';

const FileManagerQuery = graphql`
    query FileManagerQuery($first: Int, $category: FileCategory!, $entityType: String, $entityId: String) {
        files(category: $category, first: $first, entityId: $entityId, entityType: $entityType) 
                @connection(key: "Pagination_files") {
            edges {
                node {
                    ...FileViewer_files
                }
            }
        }
    }
`;

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

const FileManager = ({
  report, entityId, entityType, t, classes,
}) => <div>
    <ReportHeader report={report} />
    <Grid container={true} spacing={3} classes={{ container: classes.gridContainer }}>
        <Grid item={true} xs={6}>
            <Typography variant="h4" gutterBottom={true}>
                {t('Uploaded / Imported files')}
            </Typography>
            <Paper classes={{ root: classes.paper }} elevation={2}>
                <FileUploader entityId={entityId} uploadType='import' entityType={entityType}/>
                <QueryRenderer query={FileManagerQuery}
                               variables={{ category: 'import', entityId, entityType }}
                               render={({ props }) => {
                                 if (props) {
                                   const files = map(e => e.node, props.files.edges);
                                   return <FileViewer entityId={entityId}
                                                      entityType={entityType} files={files}/>;
                                 }
                                 return <div>Loading</div>;
                               }}/>
            </Paper>
        </Grid>
        <Grid item={true} xs={6}>
            <Typography variant="h4" gutterBottom={true}>
                {t('Generated / Exported files')}
            </Typography>
            <Paper classes={{ root: classes.paper }} elevation={2}>
                <QueryRenderer query={FileManagerQuery}
                               variables={{ category: 'export', entityId, entityType }}
                               render={({ props }) => {
                                 if (props) {
                                   const files = map(e => e.node, props.files.edges);
                                   return <FileViewer entityId={entityId}
                                                          entityType={entityType} files={files}/>;
                                 }
                                 return <div>Loading</div>;
                               }}/>
            </Paper>
        </Grid>
    </Grid>
</div>;

FileManager.propTypes = {
  entityId: PropTypes.string,
  entityType: PropTypes.string,
  report: PropTypes.object,
};

export default compose(
  inject18n,
  withStyles(styles),
)(FileManager);
