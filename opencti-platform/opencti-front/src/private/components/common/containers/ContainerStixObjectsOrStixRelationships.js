import React, { useContext } from 'react';
import * as PropTypes from 'prop-types';
import { withStyles } from '@material-ui/core/styles';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { compose, pathOr, propOr } from 'ramda';
import Typography from '@material-ui/core/Typography';
import Paper from '@material-ui/core/Paper';
import { QueryRenderer } from '../../../../relay/environment';
import ListLines from '../../../../components/list_lines/ListLines';
import ContainerStixObjectsOrStixRelationshipsLines, {
  ContainerStixObjectsOrStixRelationshipsLinesQuery,
} from './ContainerStixObjectsOrStixRelationshipsLines';
import inject18n from '../../../../components/i18n';
import Security, { KNOWLEDGE_KNUPDATE, UserContext } from '../../../../utils/Security';
import ContainerAddStixCoreObjects from './ContainerAddStixCoreObjects';

const styles = () => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '-5px 0 0 0',
    padding: 0,
    borderRadius: 6,
  },
});

const ContainerStixObjectsOrStixRelationshipsComponent = ({
  container, classes, t, paginationOptions,
}) => {
  const { helper } = useContext(UserContext);
  const isRuntimeSort = helper.isRuntimeFieldEnable();
  const dataColumns = {
    entity_type: {
      label: 'Type',
      width: '20%',
      isSortable: true,
    },
    name: {
      label: 'Name',
      width: '45%',
      isSortable: true,
    },
    created_at: {
      label: 'Creation date',
      width: '15%',
      isSortable: true,
    },
    objectMarking: {
      label: 'Marking',
      isSortable: isRuntimeSort,
    },
  };
  return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
          {t('Related entities')}
        </Typography>
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <ContainerAddStixCoreObjects
            containerId={propOr(null, 'id', container)}
            containerObjects={pathOr([], ['objects', 'edges'], container)}
            paginationOptions={paginationOptions}
            simple={true}
            targetStixCoreObjectTypes={[
              'Stix-Domain-Object',
              'Stix-Cyber-Observable',
            ]}
          />
        </Security>
        <div className="clearfix" />
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <ListLines
            dataColumns={dataColumns}
            secondaryAction={true}
            noHeaders={true}
          >
            <QueryRenderer
              query={ContainerStixObjectsOrStixRelationshipsLinesQuery}
              variables={{ id: container.id, count: 25 }}
              render={({ props }) => (
                <ContainerStixObjectsOrStixRelationshipsLines
                  container={props ? props.container : null}
                  dataColumns={dataColumns}
                  initialLoading={props === null}
                />
              )}
            />
          </ListLines>
        </Paper>
      </div>
  );
};

ContainerStixObjectsOrStixRelationshipsComponent.propTypes = {
  container: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fd: PropTypes.func,
  history: PropTypes.object,
  paginationOptions: PropTypes.object,
};

const ContainerStixObjectsOrStixRelationships = createFragmentContainer(
  ContainerStixObjectsOrStixRelationshipsComponent,
  {
    container: graphql`
      fragment ContainerStixObjectsOrStixRelationships_container on Container {
        id
        ...ContainerHeader_container
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(ContainerStixObjectsOrStixRelationships);
