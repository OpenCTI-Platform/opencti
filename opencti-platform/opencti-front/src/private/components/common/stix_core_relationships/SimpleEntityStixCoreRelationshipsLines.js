import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import { Link } from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import Avatar from '@material-ui/core/Avatar';
import { compose } from 'ramda';
import inject18n from '../../../../components/i18n';
import StixCoreRelationshipPopover from './StixCoreRelationshipPopover';
import { resolveLink } from '../../../../utils/Entity';

const styles = (theme) => ({
  paper: {
    minHeight: 280,
    height: '100%',
    margin: '10px 0 0 0',
    borderRadius: 6,
  },
  avatar: {
    width: 24,
    height: 24,
    backgroundColor: theme.palette.primary.main,
  },
  avatarDisabled: {
    width: 24,
    height: 24,
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.grey[700],
  },
});

class SimpleEntityStixCoreRelationshipsLinesContainer extends Component {
  render() {
    const {
      t,
      classes,
      entityId,
      entityLink,
      data,
      paginationOptions,
    } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Related entities (generic relation "related-to")')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          {data.stixCoreRelationships.edges.length > 0 ? (
            <List>
              {data.stixCoreRelationships.edges.map(
                (stixCoreRelationshipEdge) => {
                  const stixCoreRelationship = stixCoreRelationshipEdge.node;
                  const stixDomainObject = stixCoreRelationship.to;
                  const stixDomainObjectFrom = stixCoreRelationship.from;
                  let link = `${entityLink}/relations/${stixCoreRelationship.id}`;
                  if (stixDomainObjectFrom.id !== entityId) {
                    link = `${resolveLink(stixDomainObjectFrom.entity_type)}/${
                      stixDomainObjectFrom.id
                    }/knowledge/relations/${stixCoreRelationship.id}`;
                  }
                  return (
                    <ListItem
                      key={stixCoreRelationship.id}
                      dense={true}
                      divider={true}
                      button={true}
                      component={Link}
                      to={link}
                    >
                      <ListItemIcon>
                        <Avatar classes={{ root: classes.avatar }}>
                          {stixDomainObject.name.substring(0, 1)}
                        </Avatar>
                      </ListItemIcon>
                      <ListItemText
                        primary={stixDomainObject.name}
                        secondary={t(`entity_${stixDomainObject.entity_type}`)}
                      />
                      <ListItemSecondaryAction>
                        <StixCoreRelationshipPopover
                          stixCoreRelationshipId={stixCoreRelationship.id}
                          paginationOptions={paginationOptions}
                          disabled={stixCoreRelationship.inferred}
                        />
                      </ListItemSecondaryAction>
                    </ListItem>
                  );
                },
              )}
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
                {t('No entities of this type has been found.')}
              </span>
            </div>
          )}
        </Paper>
      </div>
    );
  }
}

SimpleEntityStixCoreRelationshipsLinesContainer.propTypes = {
  entityId: PropTypes.string,
  entityLink: PropTypes.string,
  paginationOptions: PropTypes.object,
  data: PropTypes.object,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

export const simpleEntityStixCoreRelationshipsLinesQuery = graphql`
  query SimpleEntityStixCoreRelationshipsLinesPaginationQuery(
    $fromId: String
    $toTypes: [String]
    $inferred: Boolean
    $relationship_type: String
    $firstSeenStart: DateTime
    $firstSeenStop: DateTime
    $lastSeenStart: DateTime
    $lastSeenStop: DateTime
    $confidences: [Int]
    $count: Int!
    $cursor: ID
  ) {
    ...SimpleEntityStixCoreRelationshipsLines_data
      @arguments(
        fromId: $fromId
        toTypes: $toTypes
        inferred: $inferred
        relationship_type: $relationship_type
        firstSeenStart: $firstSeenStart
        firstSeenStop: $firstSeenStop
        lastSeenStart: $lastSeenStart
        lastSeenStop: $lastSeenStop
        confidences: $confidences
        count: $count
        cursor: $cursor
      )
  }
`;

const SimpleEntityStixCoreRelationshipsLines = createPaginationContainer(
  SimpleEntityStixCoreRelationshipsLinesContainer,
  {
    data: graphql`
      fragment SimpleEntityStixCoreRelationshipsLines_data on Query
        @argumentDefinitions(
          fromId: { type: "String" }
          toTypes: { type: "[String]" }
          inferred: { type: "Boolean" }
          relationship_type: { type: "String" }
          firstSeenStart: { type: "DateTime" }
          firstSeenStop: { type: "DateTime" }
          lastSeenStart: { type: "DateTime" }
          lastSeenStop: { type: "DateTime" }
          confidences: { type: "[Int]" }
          count: { type: "Int", defaultValue: 25 }
          cursor: { type: "ID" }
        ) {
        stixCoreRelationships(
          fromId: $fromId
          toTypes: $toTypes
          inferred: $inferred
          relationship_type: $relationship_type
          firstSeenStart: $firstSeenStart
          firstSeenStop: $firstSeenStop
          lastSeenStart: $lastSeenStart
          lastSeenStop: $lastSeenStop
          confidences: $confidences
          first: $count
          after: $cursor
        ) @connection(key: "Pagination_stixCoreRelationships") {
          edges {
            node {
              id
              inferred
              to {
                id
                name
                entity_type
              }
              from {
                id
                name
                entity_type
              }
            }
          }
        }
      }
    `,
  },
  {
    direction: 'forward',
    getConnectionFromProps(props) {
      return props.data && props.data.stixCoreRelationships;
    },
    getFragmentVariables(prevVars, totalCount) {
      return {
        ...prevVars,
        count: totalCount,
      };
    },
    getVariables(props, { count, cursor }, fragmentVariables) {
      return {
        fromId: fragmentVariables.fromId,
        toTypes: fragmentVariables.toTypes,
        inferred: fragmentVariables.inferred,
        relationship_type: fragmentVariables.relationship_type,
        firstSeenStart: fragmentVariables.firstSeenStart,
        firstSeenStop: fragmentVariables.firstSeenStop,
        lastSeenStart: fragmentVariables.lastSeenStart,
        lastSeenStop: fragmentVariables.lastSeenStop,
        confidences: fragmentVariables.confidences,
        count,
        cursor,
      };
    },
    query: simpleEntityStixCoreRelationshipsLinesQuery,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(SimpleEntityStixCoreRelationshipsLines);
