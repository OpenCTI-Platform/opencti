import React, { useEffect, useState } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql, createRefetchContainer } from 'react-relay';
import { interval } from 'rxjs';
import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import withStyles from '@mui/styles/withStyles';
import List from '@mui/material/List';
import IconButton from '@mui/material/IconButton';
import { Add } from '@mui/icons-material';
import { TEN_SECONDS } from '../../../../../utils/Time';
import inject18n from '../../../../../components/i18n';
import WorkbenchFileLine from './WorkbenchFileLine';
import WorkbenchFileCreator from './WorkbenchFileCreator';

const interval$ = interval(TEN_SECONDS);

const styles = () => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    padding: '10px 15px 10px 15px',
    marginTop: -2,
    borderRadius: 6,
  },
  createButton: {
    marginTop: -15,
  },
});

const WorkbenchFileViewerBase = ({
  entity,
  handleOpenImport,
  connectors,
  relay,
  t,
  classes,
}) => {
  const { id, pendingFiles } = entity;
  const { edges } = pendingFiles;
  const [openCreate, setOpenCreate] = useState(false);

  useEffect(() => {
    // Refresh the export viewer every interval
    const subscription = interval$.subscribe(() => {
      relay.refetch({ id });
    });
    return function cleanup() {
      subscription.unsubscribe();
    };
  });

  const onCreateWorkbenchCompleted = () => {
    relay.refetch({ id });
  };

  return (
    <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
      <div style={{ height: '100%' }}>
        <div>
          <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
            {t('Analyst workbenches')}
          </Typography>
          <IconButton
            color="secondary"
            aria-label="Add"
            onClick={() => setOpenCreate(true)}
            classes={{ root: classes.createButton }}
            size="large"
          >
            <Add fontSize="small" />
          </IconButton>
        </div>
        <WorkbenchFileCreator
          handleCloseCreate={() => setOpenCreate(false)}
          openCreate={openCreate}
          onCompleted={onCreateWorkbenchCompleted}
          entity={entity}
        />
        <div className="clearfix" />
        <Paper classes={{ root: classes.paper }} variant="outlined">
          {edges.length ? (
            <List>
              {edges.map((file) => (
                <WorkbenchFileLine
                  key={file.node.id}
                  dense={true}
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

const WorkbenchFileViewerComponent = compose(
  inject18n,
  withStyles(styles),
)(WorkbenchFileViewerBase);

const WorkbenchFileViewerRefetchQuery = graphql`
  query WorkbenchFileViewerRefetchQuery($id: String!) {
    stixCoreObject(id: $id) {
      ...WorkbenchFileViewer_entity
    }
  }
`;

const WorkbenchFileViewer = createRefetchContainer(
  WorkbenchFileViewerComponent,
  {
    entity: graphql`
      fragment WorkbenchFileViewer_entity on StixCoreObject {
        id
        entity_type
        toStix
        pendingFiles(first: 1000) @connection(key: "Pagination_pendingFiles") {
          edges {
            node {
              id
              ...WorkbenchFileLine_file
              metaData {
                mimetype
              }
            }
          }
        }
      }
    `,
  },
  WorkbenchFileViewerRefetchQuery,
);

WorkbenchFileViewer.propTypes = {
  entity: PropTypes.object,
  disableImport: PropTypes.bool,
  connectors: PropTypes.object,
};

export default WorkbenchFileViewer;
