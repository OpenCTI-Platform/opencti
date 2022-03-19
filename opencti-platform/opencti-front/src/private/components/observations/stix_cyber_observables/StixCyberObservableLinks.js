import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Typography from '@mui/material/Typography';
import List from '@mui/material/List';
import { graphql, createFragmentContainer } from 'react-relay';
import ListItem from '@mui/material/ListItem';
import { Link } from 'react-router-dom';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import Paper from '@mui/material/Paper';
import inject18n from '../../../../components/i18n';
import StixCyberObservableRelationCreationFromEntity from '../../common/stix_cyber_observable_relationships/StixCyberObservableRelationshipCreationFromEntity';
import ItemIcon from '../../../../components/ItemIcon';
import StixCyberObservableRelationPopover from '../../common/stix_cyber_observable_relationships/StixCyberObservableRelationshipPopover';
import { resolveLink } from '../../../../utils/Entity';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';

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
      fsd,
      stixCyberObservableType,
      paginationOptions,
      data,
      classes,
    } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
          {t('Linked observables')}
        </Typography>
        <Security
          needs={[KNOWLEDGE_KNUPDATE]}
          placeholder={<div style={{ height: 29 }} />}
        >
          <StixCyberObservableRelationCreationFromEntity
            paginationOptions={paginationOptions}
            entityId={stixCyberObservableId}
            variant="inLine"
            entityType={stixCyberObservableType}
          />
        </Security>
        <div className="clearfix" />
        <Paper classes={{ root: classes.paper }} variant="outlined">
          <List style={{ marginTop: -10 }}>
            {data
              && data.stixCyberObservableRelationships
              && data.stixCyberObservableRelationships.edges.map(
                (stixCyberObservableRelationEdge) => {
                  const stixCyberObservableRelationshipId = stixCyberObservableRelationEdge.node;
                  const stixCyberObservable = stixCyberObservableRelationshipId.from.id
                    === stixCyberObservableId
                    ? stixCyberObservableRelationshipId.to
                    : stixCyberObservableRelationshipId.from;
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
                              style={{ width: '15%' }}
                            >
                              {t(
                                `relationship_${stixCyberObservableRelationshipId.relationship_type}`,
                              )}
                            </div>
                            <div
                              className={classes.bodyItem}
                              style={{ width: '20%' }}
                            >
                              {t(`entity_${stixCyberObservable.entity_type}`)}
                            </div>
                            <div
                              className={classes.bodyItem}
                              style={{ width: '35%' }}
                            >
                              {stixCyberObservable.observable_value}
                            </div>
                            <div
                              className={classes.bodyItem}
                              style={{ width: '15%' }}
                            >
                              {fsd(
                                stixCyberObservableRelationshipId.start_time,
                              )}
                            </div>
                            <div
                              className={classes.bodyItem}
                              style={{ width: '15%' }}
                            >
                              {fsd(stixCyberObservableRelationshipId.stop_time)}
                            </div>
                          </div>
                        }
                      />
                      <ListItemSecondaryAction>
                        <StixCyberObservableRelationPopover
                          stixCyberObservableRelationshipId={
                            stixCyberObservableRelationshipId.id
                          }
                          paginationOptions={paginationOptions}
                        />
                      </ListItemSecondaryAction>
                    </ListItem>
                  );
                },
              )}
          </List>
        </Paper>
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
        stixCyberObservableRelationships(
          elementId: $elementId
          search: $search
          first: $count
          orderBy: $orderBy
          orderMode: $orderMode
        ) @connection(key: "Pagination_stixCyberObservableRelationships") {
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
