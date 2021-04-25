import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  compose, pipe, map, assoc, filter,
} from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Typography from '@material-ui/core/Typography';
import Paper from '@material-ui/core/Paper';
import Timeline from '@material-ui/lab/Timeline';
import TimelineItem from '@material-ui/lab/TimelineItem';
import TimelineSeparator from '@material-ui/lab/TimelineSeparator';
import TimelineConnector from '@material-ui/lab/TimelineConnector';
import TimelineContent from '@material-ui/lab/TimelineContent';
import TimelineOppositeContent from '@material-ui/lab/TimelineOppositeContent';
import TimelineDot from '@material-ui/lab/TimelineDot';
import { createRefetchContainer } from 'react-relay';
import { Link } from 'react-router-dom';
import inject18n, { isNone } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import { stixDomainObjectThreatKnowledgeStixCoreRelationshipsQuery } from './StixDomainObjectThreatKnowledgeQuery';

const styles = (theme) => ({
  paper: {
    padding: 15,
  },
  itemIcon: {
    color: theme.palette.primary.main,
  },
  nested: {
    paddingLeft: theme.spacing(4),
  },
});

class StixDomainObjectTimelineComponent extends Component {
  render() {
    const {
      md, classes, data, stixDomainObjectId, entityLink,
    } = this.props;
    const stixCoreRelationships = pipe(
      map((n) => n.node),
      filter((n) => !isNone(n.start_time)),
      map((n) => (n.from.id === stixDomainObjectId
        ? assoc('targetEntity', n.to, n)
        : assoc('targetEntity', n.from, n))),
    )(data.stixCoreRelationships.edges);
    return (
      <div style={{ marginBottom: 90 }}>
        <div id="container">
          <Timeline align="alternate">
            {stixCoreRelationships.map((stixCoreRelationship) => {
              const link = `${entityLink}/relations/${stixCoreRelationship.id}`;
              return (
                <TimelineItem key={stixCoreRelationship.id}>
                  <TimelineOppositeContent>
                    <Typography variant="body2" color="textSecondary">
                      {md(stixCoreRelationship.start_time)}
                    </Typography>
                  </TimelineOppositeContent>
                  <TimelineSeparator>
                    <Link to={link}>
                      <TimelineDot color="primary" variant="outlined">
                        <ItemIcon
                          type={stixCoreRelationship.targetEntity.entity_type}
                        />
                      </TimelineDot>
                    </Link>
                    <TimelineConnector />
                  </TimelineSeparator>
                  <TimelineContent>
                    <Paper elevation={3} className={classes.paper}>
                      <Typography variant="h2">
                        {stixCoreRelationship.targetEntity.name}
                      </Typography>
                      <span style={{ color: '#a8a8a8' }}>
                        {stixCoreRelationship.description}
                      </span>
                    </Paper>
                  </TimelineContent>
                </TimelineItem>
              );
            })}
          </Timeline>
        </div>
      </div>
    );
  }
}

StixDomainObjectTimelineComponent.propTypes = {
  stixDomainObjectId: PropTypes.string,
  data: PropTypes.object,
  entityLink: PropTypes.string,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const StixDomainObjectTimeline = createRefetchContainer(
  StixDomainObjectTimelineComponent,
  {
    data: graphql`
      fragment StixDomainObjectTimeline_data on Query {
        stixCoreRelationships(
          fromId: $fromId
          fromRole: $fromRole
          toTypes: $toTypes
          relationship_type: $relationship_type
          first: $first
          orderBy: $orderBy
          orderMode: $orderMode
        ) {
          edges {
            node {
              id
              description
              start_time
              stop_time
              from {
                ... on BasicObject {
                  id
                  entity_type
                }
                ... on AttackPattern {
                  name
                  x_mitre_id
                  killChainPhases {
                    edges {
                      node {
                        id
                        phase_name
                        x_opencti_order
                      }
                    }
                  }
                }
                ... on Campaign {
                  name
                }
                ... on CourseOfAction {
                  name
                }
                ... on Individual {
                  name
                }
                ... on Organization {
                  name
                }
                ... on Sector {
                  name
                }
                ... on Indicator {
                  name
                }
                ... on Infrastructure {
                  name
                }
                ... on IntrusionSet {
                  name
                }
                ... on Position {
                  name
                }
                ... on City {
                  name
                }
                ... on Country {
                  name
                }
                ... on Region {
                  name
                }
                ... on Malware {
                  name
                  killChainPhases {
                    edges {
                      node {
                        id
                        phase_name
                        x_opencti_order
                      }
                    }
                  }
                }
                ... on ThreatActor {
                  name
                }
                ... on Tool {
                  name
                  killChainPhases {
                    edges {
                      node {
                        id
                        phase_name
                        x_opencti_order
                      }
                    }
                  }
                }
                ... on Vulnerability {
                  name
                }
                ... on Incident {
                  name
                }
              }
              killChainPhases {
                edges {
                  node {
                    id
                    phase_name
                    x_opencti_order
                  }
                }
              }
              objectMarking {
                edges {
                  node {
                    id
                    definition
                    x_opencti_color
                  }
                }
              }
              to {
                ... on BasicObject {
                  id
                  entity_type
                }
                ... on AttackPattern {
                  name
                  x_mitre_id
                  killChainPhases {
                    edges {
                      node {
                        id
                        phase_name
                        x_opencti_order
                      }
                    }
                  }
                }
                ... on Campaign {
                  name
                }
                ... on CourseOfAction {
                  name
                }
                ... on Individual {
                  name
                }
                ... on Organization {
                  name
                }
                ... on Sector {
                  name
                }
                ... on Indicator {
                  name
                }
                ... on Infrastructure {
                  name
                }
                ... on IntrusionSet {
                  name
                }
                ... on Position {
                  name
                }
                ... on City {
                  name
                }
                ... on Country {
                  name
                }
                ... on Region {
                  name
                }
                ... on Malware {
                  name
                  killChainPhases {
                    edges {
                      node {
                        id
                        phase_name
                        x_opencti_order
                      }
                    }
                  }
                }
                ... on ThreatActor {
                  name
                }
                ... on Tool {
                  name
                  killChainPhases {
                    edges {
                      node {
                        id
                        phase_name
                        x_opencti_order
                      }
                    }
                  }
                }
                ... on Vulnerability {
                  name
                }
                ... on Incident {
                  name
                }
              }
              killChainPhases {
                edges {
                  node {
                    id
                    phase_name
                    x_opencti_order
                  }
                }
              }
              objectMarking {
                edges {
                  node {
                    id
                    definition
                    x_opencti_color
                  }
                }
              }
            }
          }
        }
      }
    `,
  },
  stixDomainObjectThreatKnowledgeStixCoreRelationshipsQuery,
);

export default compose(inject18n, withStyles(styles))(StixDomainObjectTimeline);
