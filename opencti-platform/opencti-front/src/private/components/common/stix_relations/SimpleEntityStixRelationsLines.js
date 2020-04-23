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
import StixRelationPopover from './StixRelationPopover';
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

class SimpleEntityStixRelationsLinesContainer extends Component {
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
          {data.stixRelations.edges.length > 0 ? (
            <List>
              {data.stixRelations.edges.map((stixRelationEdge) => {
                const stixRelation = stixRelationEdge.node;
                const stixDomainEntity = stixRelation.to;
                const stixDomainEntityFrom = stixRelation.from;
                let link = `${entityLink}/relations/${stixRelation.id}`;
                if (stixDomainEntityFrom.id !== entityId) {
                  link = `${resolveLink(stixDomainEntityFrom.entity_type)}/${
                    stixDomainEntityFrom.id
                  }/knowledge/relations/${stixRelation.id}`;
                }
                return (
                  <ListItem
                    key={stixRelation.id}
                    dense={true}
                    divider={true}
                    button={true}
                    component={Link}
                    to={link}
                  >
                    <ListItemIcon>
                      <Avatar classes={{ root: classes.avatar }}>
                        {stixDomainEntity.name.substring(0, 1)}
                      </Avatar>
                    </ListItemIcon>
                    <ListItemText
                      primary={stixDomainEntity.name}
                      secondary={t(`entity_${stixDomainEntity.entity_type}`)}
                    />
                    <ListItemSecondaryAction>
                      <StixRelationPopover
                        stixRelationId={stixRelation.id}
                        paginationOptions={paginationOptions}
                        disabled={stixRelation.inferred}
                      />
                    </ListItemSecondaryAction>
                  </ListItem>
                );
              })}
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

SimpleEntityStixRelationsLinesContainer.propTypes = {
  entityId: PropTypes.string,
  entityLink: PropTypes.string,
  paginationOptions: PropTypes.object,
  data: PropTypes.object,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

export const simpleEntityStixRelationsLinesQuery = graphql`
  query SimpleEntityStixRelationsLinesPaginationQuery(
    $fromId: String
    $toTypes: [String]
    $inferred: Boolean
    $relationType: String
    $firstSeenStart: DateTime
    $firstSeenStop: DateTime
    $lastSeenStart: DateTime
    $lastSeenStop: DateTime
    $weights: [Int]
    $count: Int!
    $cursor: ID
  ) {
    ...SimpleEntityStixRelationsLines_data
      @arguments(
        fromId: $fromId
        toTypes: $toTypes
        inferred: $inferred
        relationType: $relationType
        firstSeenStart: $firstSeenStart
        firstSeenStop: $firstSeenStop
        lastSeenStart: $lastSeenStart
        lastSeenStop: $lastSeenStop
        weights: $weights
        count: $count
        cursor: $cursor
      )
  }
`;

const SimpleEntityStixRelationsLines = createPaginationContainer(
  SimpleEntityStixRelationsLinesContainer,
  {
    data: graphql`
      fragment SimpleEntityStixRelationsLines_data on Query
        @argumentDefinitions(
          fromId: { type: "String" }
          toTypes: { type: "[String]" }
          inferred: { type: "Boolean" }
          relationType: { type: "String" }
          firstSeenStart: { type: "DateTime" }
          firstSeenStop: { type: "DateTime" }
          lastSeenStart: { type: "DateTime" }
          lastSeenStop: { type: "DateTime" }
          weights: { type: "[Int]" }
          count: { type: "Int", defaultValue: 25 }
          cursor: { type: "ID" }
        ) {
        stixRelations(
          fromId: $fromId
          toTypes: $toTypes
          inferred: $inferred
          relationType: $relationType
          firstSeenStart: $firstSeenStart
          firstSeenStop: $firstSeenStop
          lastSeenStart: $lastSeenStart
          lastSeenStop: $lastSeenStop
          weights: $weights
          first: $count
          after: $cursor
        ) @connection(key: "Pagination_stixRelations") {
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
      return props.data && props.data.stixRelations;
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
        relationType: fragmentVariables.relationType,
        firstSeenStart: fragmentVariables.firstSeenStart,
        firstSeenStop: fragmentVariables.firstSeenStop,
        lastSeenStart: fragmentVariables.lastSeenStart,
        lastSeenStop: fragmentVariables.lastSeenStop,
        weights: fragmentVariables.weights,
        count,
        cursor,
      };
    },
    query: simpleEntityStixRelationsLinesQuery,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(SimpleEntityStixRelationsLines);
