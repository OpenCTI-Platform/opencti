import React, { useEffect } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createRefetchContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { interval } from 'rxjs';
import Grid from '@material-ui/core/Grid';
import Typography from '@material-ui/core/Typography';
import Paper from '@material-ui/core/Paper';
import { withStyles } from '@material-ui/core';
import List from '@material-ui/core/List';
import FileLine from './FileLine';
import { TEN_SECONDS } from '../../../../utils/Time';
import FileUploader from './FileUploader';
import inject18n from '../../../../components/i18n';

const interval$ = interval(TEN_SECONDS);

const styles = () => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    padding: '10px 15px 10px 15px',
    borderRadius: 6,
  },
});

const FileImportViewerBase = ({
  entity,
  disableImport,
  handleOpenImport,
  connectors,
  relay,
  t,
  classes,
}) => {
  const { id, importFiles } = entity;
  const { edges } = importFiles;
  const isContainer = entity.entity_type !== 'Report';
  useEffect(() => {
    // Refresh the export viewer every interval
    const subscription = interval$.subscribe(() => {
      relay.refetch({ id });
    });
    return function cleanup() {
      subscription.unsubscribe();
    };
  });
  return (
    <React.Fragment>
      <Grid item={true} xs={6}>
        <div style={{ height: '100%' }} className="break">
          <Typography
            variant="h4"
            gutterBottom={true}
            style={{ float: 'left' }}
          >
            {t('Uploaded files')}
          </Typography>
          <div style={{ float: 'left', marginTop: -17 }}>
            <FileUploader
              entityId={id}
              onUploadSuccess={() => relay.refetch({ id })}
            />
          </div>
          <div className="clearfix" />
          <Paper classes={{ root: classes.paper }} elevation={2}>
            {edges.length ? (
              <List>
                {edges.map((file) => (
                  <FileLine
                    key={file.node.id}
                    dense={true}
                    disableImport={isContainer || disableImport}
                    file={file.node}
                    connectors={
                      connectors && connectors[file.node.metaData.mimetype]
                    }
                    handleOpenImport={handleOpenImport}
                  />
                ))}
              </List>
            ) : (
              <div style={{ padding: 10 }}>{t('No file for the moment')}</div>
            )}
          </Paper>
        </div>
      </Grid>
    </React.Fragment>
  );
};

const FileImportViewerComponent = compose(
  inject18n,
  withStyles(styles),
)(FileImportViewerBase);

const FileImportViewerRefetchQuery = graphql`
  query FileImportViewerRefetchQuery($id: String!) {
    stixDomainObject(id: $id) {
      ...FileImportViewer_entity
    }
  }
`;

const FileImportViewer = createRefetchContainer(
  FileImportViewerComponent,
  {
    entity: graphql`
      fragment FileImportViewer_entity on StixDomainObject {
        id
        entity_type
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
  disableImport: PropTypes.bool,
  connectors: PropTypes.object,
};

export default FileImportViewer;
