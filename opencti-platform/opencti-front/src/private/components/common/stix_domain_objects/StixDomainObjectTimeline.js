import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, pipe, map, assoc } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import Timeline from '@mui/lab/Timeline';
import TimelineItem from '@mui/lab/TimelineItem';
import TimelineSeparator from '@mui/lab/TimelineSeparator';
import TimelineConnector from '@mui/lab/TimelineConnector';
import TimelineContent from '@mui/lab/TimelineContent';
import TimelineOppositeContent from '@mui/lab/TimelineOppositeContent';
import TimelineDot from '@mui/lab/TimelineDot';
import { graphql, createRefetchContainer } from 'react-relay';
import { Link } from 'react-router-dom';
import Slide from '@mui/material/Slide';
import ItemIcon from '../../../../components/ItemIcon';
import inject18n from '../../../../components/i18n';
import { stixDomainObjectThreatKnowledgeStixRelationshipsQuery } from './StixDomainObjectThreatKnowledgeQuery';
import { truncate } from '../../../../utils/String';
import { defaultSecondaryValue, defaultValue } from '../../../../utils/Graph';

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

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
    const { md, classes, data, stixDomainObjectId, entityLink, timeField } = this.props;
    const stixRelationships = pipe(
      map((n) => n.node),
      map((n) => (n.from.id === stixDomainObjectId
        ? assoc('targetEntity', n.to, n)
        : assoc('targetEntity', n.from, n))),
    )(data.stixRelationships.edges);
    return (
      <div style={{ marginBottom: 90 }}>
        <div id="container">
          <Timeline align="alternate">
            {stixRelationships.map((stixRelationship) => {
              const link = `${entityLink}/relations/${stixRelationship.id}`;
              return (
                <TimelineItem key={stixRelationship.id}>
                  <TimelineOppositeContent>
                    <Typography variant="body2" color="textSecondary">
                      {md(
                        timeField === 'technical'
                          ? stixRelationship.created
                              || stixRelationship.created_at
                          : stixRelationship.start_time
                              || stixRelationship.created_at,
                      )}
                    </Typography>
                  </TimelineOppositeContent>
                  <TimelineSeparator>
                    <Link to={link}>
                      <TimelineDot color="primary" variant="outlined">
                        <ItemIcon
                          type={stixRelationship.targetEntity.entity_type}
                        />
                      </TimelineDot>
                    </Link>
                    <TimelineConnector />
                  </TimelineSeparator>
                  <TimelineContent>
                    <Paper elevation={3} className={classes.paper}>
                      <Typography variant="h2">
                        {defaultValue(stixRelationship.targetEntity)}
                      </Typography>
                      <span style={{ color: '#a8a8a8' }}>
                        {truncate(
                          stixRelationship.description
                            && stixRelationship.description.length > 0
                            ? stixRelationship.description
                            : defaultSecondaryValue(
                              stixRelationship.targetEntity,
                            ),
                          100,
                        )}
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
  timeField: PropTypes.string,
};

const StixDomainObjectTimeline = createRefetchContainer(
  StixDomainObjectTimelineComponent,
  {
    data: graphql`
      fragment StixDomainObjectTimeline_data on Query {
        stixRelationships(
          elementId: $elementId
          elementWithTargetTypes: $elementWithTargetTypes
          relationship_type: $relationship_type
          first: $first
          orderBy: $orderBy
          orderMode: $orderMode
          filters: $filters
        ) {
          edges {
            node {
              id
              entity_type
              ... on StixMetaRelationship {
                created_at
              }
              ... on StixCoreRelationship {
                description
                created
                start_time
                stop_time
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
              from {
                ... on BasicObject {
                  id
                  entity_type
                }
                ... on AttackPattern {
                  name
                  description
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
                  description
                }
                ... on CourseOfAction {
                  name
                  description
                }
                ... on Note {
                  attribute_abstract
                  content
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
                }
                ... on Infrastructure {
                  name
                  description
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
                  description
                }
                ... on Tool {
                  name
                  description
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
                  description
                }
                ... on Incident {
                  name
                  description
                }
                ... on StixCyberObservable {
                  x_opencti_description
                  observable_value
                }
              }
              to {
                ... on BasicObject {
                  id
                  entity_type
                }
                ... on AttackPattern {
                  name
                  description
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
                  description
                }
                ... on Note {
                  attribute_abstract
                  content
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
                }
                ... on Infrastructure {
                  name
                  description
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
                  description
                }
                ... on Tool {
                  name
                  description
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
                  description
                }
                ... on Incident {
                  name
                  description
                }
                ... on StixCyberObservable {
                  x_opencti_description
                  observable_value
                }
              }
            }
          }
        }
      }
    `,
  },
  stixDomainObjectThreatKnowledgeStixRelationshipsQuery,
);

export default compose(inject18n, withStyles(styles))(StixDomainObjectTimeline);
