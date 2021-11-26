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
import { TEN_SECONDS } from '../../../../utils/Time';
import inject18n from '../../../../components/i18n';
import PendingFileLine from './PendingFileLine';
import PendingFileUploader from './PendingFileUploader';

const interval$ = interval(TEN_SECONDS);

const styles = () => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    padding: '10px 15px 10px 15px',
    borderRadius: 6,
  },
});

const FilePendingViewerBase = ({
  entity,
  disableImport,
  handleOpenImport,
  connectors,
  relay,
  t,
  classes,
}) => {
  const { id, pendingFiles } = entity;
  const { edges } = pendingFiles;
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
    <Grid item={true} xs={6}>
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
          {t('Pending files')}
        </Typography>
        <div style={{ float: 'left', marginTop: -17 }}>
          <PendingFileUploader
            entityId={id}
            onUploadSuccess={() => relay.refetch({ id })}
          />
        </div>
        <div className="clearfix" />
        <Paper classes={{ root: classes.paper }} elevation={2}>
          {edges.length ? (
            <List>
              {edges.map((file) => (
                <PendingFileLine
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

const FilePendingViewerComponent = compose(
  inject18n,
  withStyles(styles),
)(FilePendingViewerBase);

const FilePendingViewerRefetchQuery = graphql`
  query FilePendingViewerRefetchQuery($id: String!) {
    stixCoreObject(id: $id) {
      ...FilePendingViewer_entity
    }
  }
`;

const FilePendingViewer = createRefetchContainer(
  FilePendingViewerComponent,
  {
    entity: graphql`
      fragment FilePendingViewer_entity on StixCoreObject {
        id
        entity_type
        pendingFiles(first: 1000) @connection(key: "Pagination_pendingFiles") {
          edges {
            node {
              id
              ...PendingFileLine_file
              metaData {
                mimetype
              }
            }
          }
        }
      }
    `,
  },
  FilePendingViewerRefetchQuery,
);

FilePendingViewer.propTypes = {
  entity: PropTypes.object,
  disableImport: PropTypes.bool,
  connectors: PropTypes.object,
};

export default FilePendingViewer;
