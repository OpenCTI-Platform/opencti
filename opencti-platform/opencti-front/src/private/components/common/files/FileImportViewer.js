import React, { useEffect } from 'react';
import * as PropTypes from 'prop-types';
import { createRefetchContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { interval } from 'rxjs';
import Grid from '@material-ui/core/Grid';
import Typography from '@material-ui/core/Typography';
import Paper from '@material-ui/core/Paper';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core';
import FileLine from './FileLine';
import { TEN_SECONDS } from '../../../../utils/Time';
import FileUploader from './FileUploader';
import inject18n from '../../../../components/i18n';

const interval$ = interval(TEN_SECONDS);

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

const FileImportViewerBase = ({
  entity, connectors, relay, t, classes,
}) => {
  const { id, importFiles } = entity;
  const { edges } = importFiles;
  useEffect(() => {
    // Refresh the export viewer every interval
    const subscription = interval$.subscribe(() => {
      relay.refetch({ id });
    });
    return function cleanup() {
      subscription.unsubscribe();
    };
  });
  return <React.Fragment>
      <Grid item={true} xs={6}>
          <div>
              <div style={{ float: 'left' }}>
                  <Typography variant="h2" style={{ paddingTop: 15 }} gutterBottom={true}>
                      {t('Uploaded files')}
                  </Typography>
              </div>
              <div style={{ float: 'right' }}>
                  <FileUploader entityId={id} onUploadSuccess={() => relay.refetch({ id })}/>
              </div>
              <div className="clearfix" />
          </div>
          <Paper classes={{ root: classes.paper }} elevation={2}>
              {edges.length ? edges.map(file => <div style={{ marginLeft: -15 }} key={file.node.id}>
                  <FileLine file={file.node}
                            connectors={connectors && connectors[file.node.metaData.mimetype]}/>
              </div>) : <div style={{ padding: 10 }}>No file</div>}
          </Paper>
      </Grid>
  </React.Fragment>;
};

const FileImportViewerComponent = compose(
  inject18n,
  withStyles(styles),
)(FileImportViewerBase);

const FileImportViewerRefetchQuery = graphql`
    query FileImportViewerRefetchQuery($id: String!) {
        stixDomainEntity(id: $id) {
            ...FileImportViewer_entity
        }
    }
`;

const FileImportViewer = createRefetchContainer(
  FileImportViewerComponent,
  {
    entity: graphql`
        fragment FileImportViewer_entity on StixDomainEntity {
            id
            importFiles(first: 1000) @connection(key: "Pagination_importFiles") {
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
    `,
  },
  FileImportViewerRefetchQuery,
);

FileImportViewer.propTypes = {
  entity: PropTypes.object,
  connectors: PropTypes.array,
};

export default FileImportViewer;
