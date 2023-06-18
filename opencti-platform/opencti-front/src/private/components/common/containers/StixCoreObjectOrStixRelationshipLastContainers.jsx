import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { Link } from 'react-router-dom';
import { graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Skeleton from '@mui/material/Skeleton';
import Tooltip from '@mui/material/Tooltip';
import Chip from '@mui/material/Chip';
import inject18n from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import ItemIcon from '../../../../components/ItemIcon';
import ItemMarkings from '../../../../components/ItemMarkings';
import { resolveLink } from '../../../../utils/Entity';
import { hexToRGB, itemColor } from '../../../../utils/Colors';

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: 0,
    borderRadius: 6,
  },
  item: {
    height: 50,
    minHeight: 50,
    maxHeight: 50,
    paddingRight: 0,
  },
  bodyItem: {
    height: 20,
    fontSize: 13,
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
  itemIcon: {
    marginRight: 0,
    color: theme.palette.primary.main,
  },
  itemIconDisabled: {
    marginRight: 0,
    color: theme.palette.grey[700],
  },
  chipInList: {
    fontSize: 12,
    height: 20,
    float: 'left',
    textTransform: 'uppercase',
    borderRadius: 0,
  },
});

const stixCoreObjectOrStixRelationshipLastContainersQuery = graphql`
  query StixCoreObjectOrStixRelationshipLastContainersQuery(
    $first: Int
    $orderBy: ContainersOrdering
    $orderMode: OrderingMode
    $filters: [ContainersFiltering]
  ) {
    containers(
      first: $first
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) {
      edges {
        node {
          id
          created
          workflowEnabled
          entity_type
          status {
            id
            order
            template {
              name
              color
            }
          }
          creators {
            id
            name
          }
          ... on Note {
            attribute_abstract
            content
            created
          }
          ... on Opinion {
            opinion
            created
          }
          ... on ObservedData {
            first_observed
            last_observed
          }
          ... on Report {
            name
          }
          ... on Grouping {
            name
            created
          }
          ... on Case {
            name
            created
          }
          ... on Task {
            name
          }
          createdBy {
            ... on Identity {
              id
              name
              entity_type
            }
          }
          objectMarking {
            edges {
              node {
                id
                definition_type
                definition
                x_opencti_order
                x_opencti_color
              }
            }
          }
          objectLabel {
            edges {
              node {
                id
                value
                color
              }
            }
          }
          ... on ObservedData {
            objects(first: 1) {
              edges {
                node {
                  ... on StixCoreObject {
                    id
                    entity_type
                    parent_types
                    created_at
                    createdBy {
                      ... on Identity {
                        id
                        name
                        entity_type
                      }
                    }
                    objectMarking {
                      edges {
                        node {
                          id
                          definition_type
                          definition
                          x_opencti_order
                          x_opencti_color
                        }
                      }
                    }
                  }
                  ... on AttackPattern {
                    name
                    description
                    x_mitre_id
                  }
                  ... on Campaign {
                    name
                    description
                    first_seen
                    last_seen
                  }
                  ... on Note {
                    attribute_abstract
                  }
                  ... on ObservedData {
                    first_observed
                    last_observed
                  }
                  ... on Opinion {
                    opinion
                  }
                  ... on Report {
                    name
                    description
                  }
                  ... on CourseOfAction {
                    name
                    description
                  }
                  ... on Individual {
                    name
                    description
                  }
                  ... on Organization {
                    name
                    description
                  }
                  ... on Sector {
                    name
                    description
                  }
                  ... on System {
                    name
                    description
                  }
                  ... on Indicator {
                    name
                    description
                    valid_from
                  }
                  ... on Infrastructure {
                    name
                    description
                  }
                  ... on IntrusionSet {
                    name
                    description
                    first_seen
                    last_seen
                  }
                  ... on Position {
                    name
                    description
                  }
                  ... on City {
                    name
                    description
                  }
                  ... on AdministrativeArea {
                    name
                    description
                  }
                  ... on Country {
                    name
                    description
                  }
                  ... on Region {
                    name
                    description
                  }
                  ... on Malware {
                    name
                    description
                    first_seen
                    last_seen
                  }
                  ... on ThreatActor {
                    name
                    description
                    first_seen
                    last_seen
                  }
                  ... on Tool {
                    name
                    description
                  }
                  ... on Vulnerability {
                    name
                    description
                  }
                  ... on Incident {
                    name
                    description
                    first_seen
                    last_seen
                  }
                  ... on Event {
                    name
                    description
                    start_time
                    stop_time
                  }
                  ... on Channel {
                    name
                    description
                  }
                  ... on Narrative {
                    name
                    description
                  }
                  ... on Language {
                    name
                  }
                  ... on DataComponent {
                    name
                  }
                  ... on DataSource {
                    name
                  }
                  ... on Case {
                    name
                  }
                  ... on Task {
                    name
                  }
                  ... on StixCyberObservable {
                    observable_value
                    x_opencti_description
                  }
                }
              }
            }
          }
        }
      }
    }
  }
`;

class StixCoreObjectOrStixRelationshipLastContainers extends Component {
  render() {
    const { t, fsd, classes, stixCoreObjectOrStixRelationshipId, authorId } = this.props;
    const filters = [
      {
        key: 'entity_type',
        values: ['Report', 'Case', 'Observed-Data', 'Grouping'],
      },
    ];
    if (authorId) filters.push({ key: 'createdBy', values: [authorId] });
    if (stixCoreObjectOrStixRelationshipId) {
      filters.push({
        key: 'objectContains',
        values: [stixCoreObjectOrStixRelationshipId],
      });
    }
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {authorId
            ? t('Latest containers authored by this entity')
            : t('Latest containers about the object')}
        </Typography>
        <Paper classes={{ root: classes.paper }} variant="outlined">
          <QueryRenderer
            query={stixCoreObjectOrStixRelationshipLastContainersQuery}
            variables={{
              first: 8,
              orderBy: 'created',
              orderMode: 'desc',
              filters,
            }}
            render={({ props }) => {
              if (props && props.containers) {
                if (props.containers.edges.length > 0) {
                  return (
                    <List>
                      {props.containers.edges.map((containerEdge) => {
                        const container = containerEdge.node;
                        return (
                          <ListItem
                            key={container.id}
                            dense={true}
                            button={true}
                            classes={{ root: classes.item }}
                            divider={true}
                            component={Link}
                            to={`${resolveLink(container.entity_type)}/${
                              container.id
                            }`}
                          >
                            <ListItemIcon>
                              <ItemIcon type={container.entity_type} />
                            </ListItemIcon>
                            <ListItemText
                              primary={
                                <>
                                  <div
                                    className={classes.bodyItem}
                                    style={{ width: '12%' }}
                                  >
                                    <Chip
                                      classes={{ root: classes.chipInList }}
                                      style={{
                                        width: 120,
                                        backgroundColor: hexToRGB(
                                          itemColor(container.entity_type),
                                          0.08,
                                        ),
                                        color: itemColor(container.entity_type),
                                        border: `1px solid ${itemColor(
                                          container.entity_type,
                                        )}`,
                                      }}
                                      label={t(
                                        `entity_${container.entity_type}`,
                                      )}
                                    />
                                  </div>
                                  <Tooltip title={container.name}>
                                    <div
                                      className={classes.bodyItem}
                                      style={{ width: '37%' }}
                                    >
                                      {container.name}
                                    </div>
                                  </Tooltip>
                                  <div
                                    className={classes.bodyItem}
                                    style={{ width: '20%' }}
                                  >
                                    {container.createdBy?.name ?? ''}
                                  </div>
                                  <div
                                    className={classes.bodyItem}
                                    style={{ width: '12%' }}
                                  >
                                    {fsd(container.created)}
                                  </div>
                                  <div
                                    className={classes.bodyItem}
                                    style={{ width: '15%' }}
                                  >
                                    <ItemMarkings
                                      variant="inList"
                                      markingDefinitionsEdges={
                                        container.objectMarking.edges
                                      }
                                      limit={1}
                                    />
                                  </div>
                                </>
                              }
                            />
                          </ListItem>
                        );
                      })}
                    </List>
                  );
                }
                return (
                  <div
                    style={{
                      display: 'table',
                      height: '100%',
                      width: '100%',
                      paddingTop: 15,
                      paddingBottom: 15,
                    }}
                  >
                    <span
                      style={{
                        display: 'table-cell',
                        verticalAlign: 'middle',
                        textAlign: 'center',
                      }}
                    >
                      {t('No containers about this entity.')}
                    </span>
                  </div>
                );
              }
              return (
                <List>
                  {Array.from(Array(5), (e, i) => (
                    <ListItem
                      key={i}
                      dense={true}
                      divider={true}
                      button={false}
                    >
                      <ListItemIcon classes={{ root: classes.itemIcon }}>
                        <Skeleton
                          animation="wave"
                          variant="circular"
                          width={30}
                          height={30}
                        />
                      </ListItemIcon>
                      <ListItemText
                        primary={
                          <Skeleton
                            animation="wave"
                            variant="rectangular"
                            width="90%"
                            height={15}
                            style={{ marginBottom: 10 }}
                          />
                        }
                        secondary={
                          <Skeleton
                            animation="wave"
                            variant="rectangular"
                            width="90%"
                            height={15}
                          />
                        }
                      />
                    </ListItem>
                  ))}
                </List>
              );
            }}
          />
        </Paper>
      </div>
    );
  }
}

StixCoreObjectOrStixRelationshipLastContainers.propTypes = {
  stixCoreObjectOrStixRelationshipId: PropTypes.string,
  authorId: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  fsd: PropTypes.func,
};

export default R.compose(
  inject18n,
  withStyles(styles),
)(StixCoreObjectOrStixRelationshipLastContainers);
