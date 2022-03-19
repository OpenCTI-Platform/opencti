import React, { useEffect } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql, createRefetchContainer } from 'react-relay';
import { interval } from 'rxjs';
import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import withStyles from '@mui/styles/withStyles';
import List from '@mui/material/List';
import FileLine from './FileLine';
import { TEN_SECONDS } from '../../../../utils/Time';
import FileUploader from './FileUploader';
import inject18n from '../../../../components/i18n';
import FreeTextUploader from './FreeTextUploader';

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
    <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
      <div style={{ height: '100%' }} className="break">
        <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
          {t('Uploaded files')}
        </Typography>
        <div style={{ float: 'left', marginTop: -17 }}>
          <FileUploader
            entityId={id}
            onUploadSuccess={() => relay.refetch({ id })}
          />
          <FreeTextUploader
            entityId={id}
            onUploadSuccess={() => relay.refetch({ id })}
          />
        </div>
        <div className="clearfix" />
        <Paper classes={{ root: classes.paper }} variant="outlined">
          {edges.length ? (
            <List>
              {edges.map((file) => (
                <FileLine
                  key={file.node.id}
                  dense={true}
                  disableImport={disableImport}
                  file={file.node}
                  connectors={
                    connectors && connectors[file.node.metaData.mimetype]
                  }
                  handleOpenImport={handleOpenImport}
                />
              ))}
            </List>
          ) : (
            <div style={{ display: 'table', height: '100%', width: '100%' }}>
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
  );
};

const FileImportViewerComponent = compose(
  inject18n,
  withStyles(styles),
)(FileImportViewerBase);

const FileImportViewerRefetchQuery = graphql`
  query FileImportViewerRefetchQuery($id: String!) {
    stixCoreObject(id: $id) {
      ...FileImportViewer_entity
    }
  }
`;

const FileImportViewer = createRefetchContainer(
  FileImportViewerComponent,
  {
    entity: graphql`
      fragment FileImportViewer_entity on StixCoreObject {
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
