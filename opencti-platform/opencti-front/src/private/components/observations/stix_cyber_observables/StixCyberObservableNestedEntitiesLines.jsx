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
import StixNestedRefRelationshipPopover from '../../common/stix_nested_ref_relationships/StixNestedRefRelationshipPopover';
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
    borderRadius: 0,
  },
});

class StixCyberObservableNestedEntitiesLinesComponent extends Component {
  render() {
    const { stixCyberObservableId, t, fsd, paginationOptions, data, classes } = this.props;
    return (
      <div>
        {data
          && data.stixNestedRefRelationships
          && data.stixNestedRefRelationships.edges.map(
            (stixNestedRefRelationEdge) => {
              const stixNestedRefRelationship = stixNestedRefRelationEdge.node;
              const stixCoreObject = stixNestedRefRelationship.from.id
                === stixCyberObservableId
                ? stixNestedRefRelationship.to
                : stixNestedRefRelationship.from;
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
                          style={{ width: '10%' }}
                        >
                          <Chip
                            variant="outlined"
                            classes={{ root: classes.chipInList }}
                            style={{ width: 120 }}
                            color="primary"
                            label={t(
                              `relationship_${stixNestedRefRelationship.relationship_type}`,
                            )}
                          />
                        </div>
                        <div
                          className={classes.bodyItem}
                          style={{ width: '10%' }}
                        >
                          <Chip
                            classes={{ root: classes.chipInList }}
                            style={{
                              backgroundColor: hexToRGB(
                                itemColor(stixCoreObject.entity_type),
                                0.08,
                              ),
                              color: itemColor(stixCoreObject.entity_type),
                              border: `1px solid ${itemColor(
                                stixCoreObject.entity_type,
                              )}`,
                            }}
                            label={t(`entity_${stixCoreObject.entity_type}`)}
                          />
                        </div>
                        <div
                          className={classes.bodyItem}
                          style={{ width: '22%' }}
                        >
                          {defaultValue(stixCoreObject)}
                        </div>
                        <div
                          className={classes.bodyItem}
                          style={{ width: '12%' }}
                        >
                          {(stixCoreObject.creators ?? [])
                            .map((c) => c?.name)
                            .join(', ')}
                        </div>
                        <div
                          className={classes.bodyItem}
                          style={{ width: '15%' }}
                        >
                          {fsd(stixNestedRefRelationship.start_time)}
                        </div>
                        <div
                          className={classes.bodyItem}
                          style={{ width: '15%' }}
                        >
                          {fsd(stixNestedRefRelationship.stop_time)}
                        </div>
                      </div>
                    }
                  />
                  <ListItemSecondaryAction>
                    <StixNestedRefRelationshipPopover
                      stixNestedRefRelationshipId={
                        stixNestedRefRelationship.id
                      }
                      paginationOptions={paginationOptions}
                    />
                  </ListItemSecondaryAction>
                </ListItem>
              );
            },
          )}
      </div>
    );
  }
}

StixCyberObservableNestedEntitiesLinesComponent.propTypes = {
  stixCyberObservableId: PropTypes.string,
  paginationOptions: PropTypes.object,
  data: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

export const stixCyberObservableNestedEntitiesLinesQuery = graphql`
  query StixCyberObservableNestedEntitiesLinesQuery(
    $elementId: String
    $search: String
    $count: Int!
    $orderBy: StixRefRelationshipsOrdering
    $orderMode: OrderingMode
  ) {
    ...StixCyberObservableNestedEntitiesLines_data
      @arguments(
        elementId: $elementId
        search: $search
        count: $count
        orderBy: $orderBy
        orderMode: $orderMode
      )
  }
`;

const StixCyberObservableNestedEntitiesLines = createFragmentContainer(
  StixCyberObservableNestedEntitiesLinesComponent,
  {
    data: graphql`
      fragment StixCyberObservableNestedEntitiesLines_data on Query
      @argumentDefinitions(
        elementId: { type: "String" }
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        orderBy: { type: "StixRefRelationshipsOrdering" }
        orderMode: { type: "OrderingMode" }
      ) {
        stixNestedRefRelationships(
          elementId: $elementId
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
              creators {
                id
                name
              }
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
                ... on ThreatActorGroup {
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
                ... on Report {
                    name
                }
                ... on Grouping {
                    name
                }
                ... on Note {
                    attribute_abstract
                    content
                }
                ... on Opinion {
                    opinion
                }
                ... on ObservedData {
                    name
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
                ... on ThreatActorGroup {
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
                ... on Report {
                    name
                }
                ... on Grouping {
                    name
                }
                ... on Note {
                    attribute_abstract
                    content
                }
                ... on Opinion {
                    opinion
                }
                ... on ObservedData {
                    name
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
)(StixCyberObservableNestedEntitiesLines);
