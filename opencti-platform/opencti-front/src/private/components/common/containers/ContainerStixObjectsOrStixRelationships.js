import React, { useContext } from 'react';
import * as PropTypes from 'prop-types';
import withStyles from '@mui/styles/withStyles';
import { graphql, createFragmentContainer } from 'react-relay';
import { compose, pathOr, propOr } from 'ramda';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import { QueryRenderer } from '../../../../relay/environment';
import ListLines from '../../../../components/list_lines/ListLines';
import ContainerStixObjectsOrStixRelationshipsLines, {
  ContainerStixObjectsOrStixRelationshipsLinesQuery,
} from './ContainerStixObjectsOrStixRelationshipsLines';
import inject18n from '../../../../components/i18n';
import Security, {
  KNOWLEDGE_KNUPDATE,
  UserContext,
} from '../../../../utils/Security';
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
  container,
  classes,
  t,
  paginationOptions,
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
      width: '35%',
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
          containerStixCoreObjects={pathOr([], ['objects', 'edges'], container)}
          paginationOptions={paginationOptions}
          simple={true}
          targetStixCoreObjectTypes={[
            'Stix-Domain-Object',
            'Stix-Cyber-Observable',
          ]}
        />
      </Security>
      <div className="clearfix" />
      <Paper classes={{ root: classes.paper }} variant="outlined">
        <ListLines
          dataColumns={dataColumns}
          secondaryAction={true}
          noHeaders={true}
          noTopMargin={true}
        >
          <QueryRenderer
            query={ContainerStixObjectsOrStixRelationshipsLinesQuery}
            variables={{ id: container.id, count: 25 }}
            render={({ props }) => {
              if (
                props
                && props.container
                && props.container.objects
                && props.container.objects.edges.length === 0
              ) {
                return <div />;
              }
              return (
                <ContainerStixObjectsOrStixRelationshipsLines
                  container={props ? props.container : null}
                  dataColumns={dataColumns}
                  initialLoading={props === null}
                />
              );
            }}
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
        objects {
          edges {
            node {
              ... on BasicObject {
                id
              }
            }
          }
        }
        ...ContainerHeader_container
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(ContainerStixObjectsOrStixRelationships);
