import React from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { compose, map } from 'ramda';
import Grid from '@material-ui/core/Grid';
import Typography from '@material-ui/core/Typography';
import Paper from '@material-ui/core/Paper';
import { withStyles } from '@material-ui/core';
import IconButton from '@material-ui/core/IconButton';
import { DonutSmall, DonutLarge } from '@material-ui/icons';
import inject18n from '../../../../components/i18n';
import FileUploader from './FileUploader';
import FileViewer from './FileViewer';
import { QueryRenderer } from '../../../../relay/environment';
import ReportHeader from '../../reports/ReportHeader';

const FileManagerQuery = graphql`
    query FileManagerQuery($category: FileCategory!, $entityId: String!, $first: Int) {
        files(category: $category, entityId: $entityId , first: $first) 
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
}) => {
  const exportPartial = () => { console.log('exportPartial'); };
  const exportComplete = () => { console.log('exportComplete'); };
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
                        <FileUploader entityId={entityId}/>
                    </div>
                    <div className="clearfix" />
                </div>
                <Paper classes={{ root: classes.paper }} elevation={2}>
                    <QueryRenderer query={FileManagerQuery}
                        variables={{ category: 'import', entityId }}
                        render={({ props }) => {
                          if (props) {
                            const files = map(e => e.node, props.files.edges);
                            return <FileViewer entityId={entityId} files={files}/>;
                          }
                          return <div>Loading</div>;
                        }}/>
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
                    <QueryRenderer query={FileManagerQuery}
                        variables={{ category: 'export', entityId }}
                        render={({ props }) => {
                          if (props) {
                            const files = map(e => e.node, props.files.edges);
                            return <FileViewer entityId={entityId} files={files}/>;
                          }
                          return <div>Loading</div>;
                        }}/>
                </Paper>
            </Grid>
        </Grid>
    </div>;
};

FileManager.propTypes = {
  entityId: PropTypes.string,
  entityType: PropTypes.string,
  nsdt: PropTypes.func,
  report: PropTypes.object,
};

export default compose(
  inject18n,
  withStyles(styles),
)(FileManager);
