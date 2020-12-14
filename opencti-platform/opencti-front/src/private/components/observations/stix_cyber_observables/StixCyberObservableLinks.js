import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Typography from '@material-ui/core/Typography';
import List from '@material-ui/core/List';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import ListItem from '@material-ui/core/ListItem';
import { Link } from 'react-router-dom';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import inject18n from '../../../../components/i18n';
import StixCyberObservableRelationCreationFromEntity from '../../common/stix_cyber_observable_relationships/StixCyberObservableRelationshipCreationFromEntity';
import ItemIcon from '../../../../components/ItemIcon';
import StixCyberObservableRelationPopover from '../../common/stix_cyber_observable_relationships/StixCyberObservableRelationshipPopover';
import { resolveLink } from '../../../../utils/Entity';

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: 0,
    padding: '25px 15px 15px 15px',
    borderRadius: 6,
  },
  item: {
    paddingLeft: 10,
    height: 50,
  },
  itemIcon: {
    color: theme.palette.primary.main,
  },
  bodyItem: {
    height: 20,
    fontSize: 13,
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  goIcon: {
    position: 'absolute',
    right: -10,
  },
  itemIconDisabled: {
    color: theme.palette.grey[700],
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.grey[700],
  },
});

export const stixCyberObservableLinksQuery = graphql`
  query StixCyberObservableLinksQuery(
    $elementId: String
    $search: String
    $count: Int!
    $orderBy: StixCyberObservableRelationshipsOrdering
    $orderMode: OrderingMode
  ) {
    ...StixCyberObservableLinks_data
      @arguments(
        elementId: $elementId
        search: $search
        count: $count
        orderBy: $orderBy
        orderMode: $orderMode
      )
  }
`;

class StixCyberObservableLinksComponent extends Component {
  render() {
    const {
      stixCyberObservableId,
      t,
      nsd,
      stixCyberObservableType,
      paginationOptions,
      data,
      classes,
    } = this.props;
    return (
      <div>
        <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
          {t('Linked observables')}
        </Typography>
        <StixCyberObservableRelationCreationFromEntity
          paginationOptions={paginationOptions}
          entityId={stixCyberObservableId}
          isRelationReversed={false}
          variant="inLine"
          entityType={stixCyberObservableType}
        />
        <div className="clearfix" />
        <List>
          {data && data.stixCyberObservableRelationshipsOfElement
            ? data.stixCyberObservableRelationshipsOfElement.edges.map(
              (stixCyberObservableRelationEdge) => {
                const stixCyberObservableRelation = stixCyberObservableRelationEdge.node;
                const stixCyberObservable = stixCyberObservableRelation.from.id
                    === stixCyberObservableId
                  ? stixCyberObservableRelation.to
                  : stixCyberObservableRelation.from;
                const link = `${resolveLink(
                  stixCyberObservable.entity_type,
                )}/${stixCyberObservable.id}`;
                return (
                    <ListItem
                      key={stixCyberObservable.id}
                      classes={{ root: classes.item }}
                      divider={true}
                      button={true}
                      component={Link}
                      to={link}
                    >
                      <ListItemIcon classes={{ root: classes.itemIcon }}>
                        <ItemIcon type={stixCyberObservable.entity_type} />
                      </ListItemIcon>
                      <ListItemText
                        primary={
                          <div>
                            <div
                              className={classes.bodyItem}
                              style={{ width: '10%' }}
                            >
                              {stixCyberObservableRelation.relationship_type}
                            </div>
                            <div
                              className={classes.bodyItem}
                              style={{ width: '20%' }}
                            >
                              {t(`entity_${stixCyberObservable.entity_type}`)}
                            </div>
                            <div
                              className={classes.bodyItem}
                              style={{ width: '40%' }}
                            >
                              {stixCyberObservable.observable_value}
                            </div>
                            <div
                              className={classes.bodyItem}
                              style={{ width: '15%' }}
                            >
                              {nsd(stixCyberObservableRelation.start_time)}
                            </div>
                            <div
                              className={classes.bodyItem}
                              style={{ width: '15%' }}
                            >
                              {nsd(stixCyberObservableRelation.stop_time)}
                            </div>
                          </div>
                        }
                      />
                      <ListItemSecondaryAction>
                        <StixCyberObservableRelationPopover
                          stixCyberObservableRelationId={
                            stixCyberObservableRelation.id
                          }
                          paginationOptions={paginationOptions}
                        />
                      </ListItemSecondaryAction>
                    </ListItem>
                );
              },
            )
            : ''}
        </List>
      </div>
    );
  }
}

StixCyberObservableLinksComponent.propTypes = {
  stixCyberObservableId: PropTypes.string,
  stixCyberObservableType: PropTypes.string,
  paginationOptions: PropTypes.object,
  data: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

const StixCyberObservableLinks = createFragmentContainer(
  StixCyberObservableLinksComponent,
  {
    data: graphql`
      fragment StixCyberObservableLinks_data on Query
      @argumentDefinitions(
        elementId: { type: "String" }
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        orderBy: { type: "StixCyberObservableRelationshipsOrdering" }
        orderMode: { type: "OrderingMode" }
      ) {
        stixCyberObservableRelationshipsOfElement(
          elementId: $elementId
          search: $search
          first: $count
          orderBy: $orderBy
          orderMode: $orderMode
        )
          @connection(
            key: "Pagination_stixCyberObservableRelationshipsOfElement"
          ) {
          edges {
            node {
              id
              relationship_type
              start_time
              stop_time
              from {
                ... on StixCyberObservable {
                  id
                  entity_type
                  observable_value
                  created_at
                  updated_at
                }
              }
              to {
                ... on StixCyberObservable {
                  id
                  entity_type
                  observable_value
                  created_at
                  updated_at
                }
              }
            }
          }
          pageInfo {
            endCursor
            hasNextPage
            globalCount
          }
        }
      }
    `,
  },
);

export default compose(inject18n, withStyles(styles))(StixCyberObservableLinks);
