import React, { useEffect } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { graphql, createRefetchContainer } from 'react-relay';
import { interval } from 'rxjs';
import withStyles from '@mui/styles/withStyles';
import { Grid, List, Paper, Typography } from '@components';
import FileLine from './FileLine';
import { TEN_SECONDS } from '../../../../utils/Time';
import inject18n from '../../../../components/i18n';

const interval$ = interval(TEN_SECONDS);

const styles = () => ({
  paper: {
    padding: '10px 15px 10px 15px',
    marginTop: 7,
    borderRadius: 4,
  },
});

const FileExternalReferencesViewerBase = ({
  entity,
  disableImport,
  handleOpenImport,
  connectors,
  relay,
  t,
  classes,
}) => {
  const { id, externalReferences } = entity;
  const sortByLastModified = R.sortBy(R.prop('lastModified'));
  const allFiles = R.pipe(
    R.map((n) => n.node.importFiles.edges),
    R.flatten,
    R.filter((n) => n.node !== null),
    R.map((n) => n.node),
    sortByLastModified,
  )(externalReferences.edges);
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
    <Grid size={12}>
      <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
        {t('External references files')}
      </Typography>
      <div className="clearfix" />
      <Paper classes={{ root: classes.paper }} className={'paper-for-grid'} variant="outlined">
        {allFiles.length ? (
          <List>
            {allFiles.map((file) => file && (
              <FileLine
                key={file.id}
                dense={true}
                disableImport={isContainer || disableImport}
                file={file}
                connectors={connectors && connectors[file.metaData.mimetype]}
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
    </Grid>
  );
};

const FileExternalReferencesViewerComponent = R.compose(
  inject18n,
  withStyles(styles),
)(FileExternalReferencesViewerBase);

const FileExternalReferencesViewerRefetchQuery = graphql`
  query FileExternalReferencesViewerRefetchQuery($id: String!) {
    stixDomainObject(id: $id) {
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
  }
`;

const FileExternalReferencesViewer = createRefetchContainer(
  FileExternalReferencesViewerComponent,
  {
    entity: graphql`
      fragment FileExternalReferencesViewer_entity on StixCoreObject {
        id
        entity_type
        externalReferences {
          edges {
            node {
              source_name
              url
              description
              importFiles(first: 500)
              @connection(key: "Pagination_importFiles") {
                edges {
                  node {
                    id
                    lastModified
                    ...FileLine_file
                    metaData {
                      mimetype
                    }
                  }
                }
              }
            }
          }
        }
      }
    `,
  },
  FileExternalReferencesViewerRefetchQuery,
);

FileExternalReferencesViewer.propTypes = {
  entity: PropTypes.object,
  disableImport: PropTypes.bool,
  connectors: PropTypes.object,
};

export default FileExternalReferencesViewer;
