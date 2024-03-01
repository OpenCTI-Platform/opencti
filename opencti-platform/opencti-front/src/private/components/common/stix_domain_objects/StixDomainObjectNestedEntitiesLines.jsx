import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import { graphql, createFragmentContainer } from 'react-relay';
import ListItem from '@mui/material/ListItem';
import { Link } from 'react-router-dom';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import Chip from '@mui/material/Chip';
import inject18n from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import StixNestedRefRelationshipPopover from '../stix_nested_ref_relationships/StixNestedRefRelationshipPopover';
import { resolveLink } from '../../../../utils/Entity';
import { defaultValue } from '../../../../utils/Graph';
import { hexToRGB, itemColor } from '../../../../utils/Colors';

const styles = (theme) => ({
  item: {
    paddingLeft: 10,
    height: 50,
  },
  itemIcon: {
    color: theme.palette.primary.main,
  },
  itemHead: {
    paddingLeft: 10,
    textTransform: 'uppercase',
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
  chipInList: {
    fontSize: 12,
    height: 20,
    float: 'left',
    textTransform: 'uppercase',
    borderRadius: 4,
  },
});

class StixDomainObjectNestedEntitiesLinesComponent extends Component {
  render() {
    const { stixDomainObjectId, t, fsd, paginationOptions, data, classes } = this.props;
    return (
      <div>
        {data
          && data.stixNestedRefRelationships
          && data.stixNestedRefRelationships.edges.map((edge) => {
            const { node } = edge;
            const stixCoreObject = node.from.id === stixDomainObjectId ? node.to : node.from;
            const link = `${resolveLink(stixCoreObject.entity_type)}/${
              stixCoreObject.id
            }`;
            return (
              <ListItem
                key={stixCoreObject.id}
                classes={{ root: classes.item }}
                divider={true}
                button={true}
                component={Link}
                to={link}
              >
                <ListItemIcon classes={{ root: classes.itemIcon }}>
                  <ItemIcon type={stixCoreObject.entity_type} />
                </ListItemIcon>
                <ListItemText
                  primary={
                    <div>
                      <div
                        className={classes.bodyItem}
                        style={{ width: '20%' }}
                      >
                        <Chip
                          variant="outlined"
                          classes={{ root: classes.chipInList }}
                          style={{ width: 120 }}
                          color="primary"
                          label={t(`relationship_${node.relationship_type}`)}
                        />
                      </div>
                      <div
                        className={classes.bodyItem}
                        style={{ width: '20%' }}
                      >
                        <Chip
                          classes={{ root: classes.chipInList }}
                          style={{
                            width: 140,
                            backgroundColor: hexToRGB(
                              itemColor(stixCoreObject.entity_type),
                              0.08,
                            ),
                            color: itemColor(stixCoreObject.entity_type),
                            border: `1px solid ${itemColor(
                              stixCoreObject.entity_type,
                            )}`,
                          }}
                          label={
                            <>
                              <ItemIcon
                                variant="inline"
                                type={stixCoreObject.entity_type}
                              />
                              {stixCoreObject.relationship_type
                                ? t(
                                  `relationship_${stixCoreObject.entity_type}`,
                                )
                                : t(`entity_${stixCoreObject.entity_type}`)}
                            </>
                          }
                        />
                      </div>
                      <div
                        className={classes.bodyItem}
                        style={{ width: '40%' }}
                      >
                        {defaultValue(stixCoreObject)}
                      </div>
                      <div className={classes.bodyItem}>
                        {fsd(node.start_time)}
                      </div>
                    </div>
                  }
                />
                <ListItemSecondaryAction>
                  <StixNestedRefRelationshipPopover
                    stixNestedRefRelationshipId={node.id}
                    paginationOptions={paginationOptions}
                  />
                </ListItemSecondaryAction>
              </ListItem>
            );
          })}
      </div>
    );
  }
}

StixDomainObjectNestedEntitiesLinesComponent.propTypes = {
  stixDomainObjectId: PropTypes.string,
  paginationOptions: PropTypes.object,
  data: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

export const stixDomainObjectNestedEntitiesLinesQuery = graphql`
  query StixDomainObjectNestedEntitiesLinesQuery(
    $fromOrToId: String
    $search: String
    $count: Int
    $orderBy: StixRefRelationshipsOrdering
    $orderMode: OrderingMode
  ) {
    ...StixDomainObjectNestedEntitiesLines_data
      @arguments(
        fromOrToId: $fromOrToId
        search: $search
        count: $count
        orderBy: $orderBy
        orderMode: $orderMode
      )
  }
`;

const StixDomainObjectNestedEntitiesLines = createFragmentContainer(
  StixDomainObjectNestedEntitiesLinesComponent,
  {
    data: graphql`
      fragment StixDomainObjectNestedEntitiesLines_data on Query
      @argumentDefinitions(
        fromOrToId: { type: "String" }
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        orderBy: { type: "StixRefRelationshipsOrdering" }
        orderMode: { type: "OrderingMode" }
      ) {
        stixNestedRefRelationships(
          fromOrToId: $fromOrToId
          search: $search
          first: $count
          orderBy: $orderBy
          orderMode: $orderMode
        ) @connection(key: "Pagination_stixNestedRefRelationships") {
          edges {
            node {
              id
              relationship_type
              start_time
              stop_time
              from {
                ... on BasicObject {
                  id
                  entity_type
                  parent_types
                }
                ... on StixObject {
                  created_at
                  updated_at
                }
                ... on AttackPattern {
                  name
                  description
                }
                ... on Campaign {
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
                }
                ... on Infrastructure {
                  name
                }
                ... on IntrusionSet {
                  name
                  description
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
                }
                ... on MalwareAnalysis {
                  result_name
                }
                ... on ThreatActor {
                  name
                  description
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
                }
                ... on Event {
                  name
                  description
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
                ... on StixCyberObservable {
                  observable_value
                }
              }
              to {
                ... on BasicObject {
                  id
                  entity_type
                  parent_types
                }
                ... on StixObject {
                  created_at
                  updated_at
                }
                ... on AttackPattern {
                  name
                  description
                }
                ... on Campaign {
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
                }
                ... on Infrastructure {
                  name
                }
                ... on IntrusionSet {
                  name
                  description
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
                }
                ... on MalwareAnalysis {
                  result_name
                }
                ... on ThreatActor {
                  name
                  description
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
                }
                ... on Event {
                  name
                  description
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
                ... on StixCyberObservable {
                  observable_value
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

export default compose(
  inject18n,
  withStyles(styles),
)(StixDomainObjectNestedEntitiesLines);
