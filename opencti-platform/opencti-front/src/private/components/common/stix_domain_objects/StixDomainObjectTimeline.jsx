import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, pipe, map, assoc } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import withTheme from '@mui/styles/withTheme';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import Timeline from '@mui/lab/Timeline';
import TimelineItem from '@mui/lab/TimelineItem';
import TimelineSeparator from '@mui/lab/TimelineSeparator';
import TimelineConnector from '@mui/lab/TimelineConnector';
import TimelineContent from '@mui/lab/TimelineContent';
import TimelineOppositeContent from '@mui/lab/TimelineOppositeContent';
import Tooltip from '@mui/material/Tooltip';
import TimelineDot from '@mui/lab/TimelineDot';
import { graphql, createRefetchContainer } from 'react-relay';
import { Link } from 'react-router-dom';
import Slide from '@mui/material/Slide';
import ItemIcon from '../../../../components/ItemIcon';
import inject18n from '../../../../components/i18n';
import { stixDomainObjectThreatKnowledgeStixRelationshipsQuery } from './StixDomainObjectThreatKnowledgeQuery';
import { truncate } from '../../../../utils/String';
import { getSecondaryRepresentative, getMainRepresentative } from '../../../../utils/defaultRepresentatives';
import { itemColor } from '../../../../utils/Colors';

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
    const {
      fldt,
      classes,
      theme,
      data,
      stixDomainObjectId,
      entityLink,
      timeField,
      t,
    } = this.props;
    const stixRelationships = pipe(
      map((n) => n.node),
      map((n) => (n.from && n.from.id === stixDomainObjectId
        ? assoc('targetEntity', n.to, n)
        : assoc('targetEntity', n.from, n))),
    )(data.stixRelationships.edges);
    return (
      <div style={{ marginBottom: 90 }}>
        <div id="container">
          <Timeline position="alternate">
            {stixRelationships.map((stixRelationship) => {
              let link = null;
              if (
                stixRelationship.parent_types.includes('stix-core-relationship')
              ) {
                link = `${entityLink}/relations/${stixRelationship.id}`;
              } else if (
                stixRelationship.entity_type === 'stix-sighting-relationship'
              ) {
                link = `${entityLink}/sightings/${stixRelationship.id}`;
              }
              const restricted = stixRelationship.targetEntity === null;
              return (
                <TimelineItem key={stixRelationship.id}>
                  <TimelineOppositeContent
                    sx={{ paddingTop: '18px' }}
                    color="text.secondary"
                  >
                    {fldt(
                      timeField === 'technical'
                        ? stixRelationship.created
                        || stixRelationship.created_at
                        : stixRelationship.start_time
                          || stixRelationship.first_seen
                          || stixRelationship.created_at,
                    )}
                  </TimelineOppositeContent>
                  <TimelineSeparator>
                    {link ? (
                      <Link to={link}>
                        <Tooltip
                          title={
                            !restricted
                              ? getMainRepresentative(stixRelationship.targetEntity)
                              : t('Restricted')
                          }
                        >
                          <TimelineDot
                            sx={{
                              borderColor: !restricted
                                ? itemColor(
                                    stixRelationship.targetEntity.entity_type,
                                  )
                                : theme.palette.primary.main,
                            }}
                            variant="outlined"
                          >
                            <ItemIcon
                              type={
                                !restricted
                                  ? stixRelationship.targetEntity.entity_type
                                  : t('Restricted')
                              }
                            />
                          </TimelineDot>
                        </Tooltip>
                      </Link>
                    ) : (
                      <Tooltip
                        title={
                          !restricted
                            ? getMainRepresentative(stixRelationship.targetEntity)
                            : t('Restricted')
                        }
                      >
                        <TimelineDot
                          sx={{
                            borderColor: !restricted
                              ? itemColor(
                                  stixRelationship.targetEntity.entity_type,
                                )
                              : theme.palette.primary.main,
                          }}
                          variant="outlined"
                        >
                          <ItemIcon
                            type={
                              !restricted
                                ? stixRelationship.targetEntity.entity_type
                                : t('Restricted')
                            }
                          />
                        </TimelineDot>
                      </Tooltip>
                    )}
                    <TimelineConnector />
                  </TimelineSeparator>
                  <TimelineContent>
                    <Paper variant="outlined" className={classes.paper}>
                      <Typography variant="h2">
                        {!restricted
                          ? truncate(
                              getMainRepresentative(stixRelationship.targetEntity),
                              50,
                            )
                          : t('Restricted')}
                      </Typography>
                      <span style={{ color: '#a8a8a8' }}>
                        {truncate(

                          stixRelationship.description
                          && stixRelationship.description.length > 0
                            ? stixRelationship.description
                            : !restricted
                                ? getSecondaryRepresentative(
                                    stixRelationship.targetEntity,
                                  )
                                : t('Restricted'),
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
          fromOrToId: $fromOrToId
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
              parent_types
              ... on StixRefRelationship {
                created_at
              }
              ... on StixCoreRelationship {
                description
                created
                start_time
                stop_time
                killChainPhases {
                  id
                  phase_name
                  x_opencti_order
                }
                objectMarking {
                  id
                  definition_type
                  definition
                  x_opencti_order
                  x_opencti_color
                }
              }
              ... on StixSightingRelationship {
                created
                first_seen
                last_seen
                objectMarking {
                  id
                  definition_type
                  definition
                  x_opencti_order
                  x_opencti_color
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
                    id
                    phase_name
                    x_opencti_order
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
                ... on Opinion {
                  opinion
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
                  killChainPhases {
                    id
                    phase_name
                    x_opencti_order
                  }
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
                  killChainPhases {
                    id
                    phase_name
                    x_opencti_order
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
                ... on Creator {
                  name
                }
                ... on MarkingDefinition {
                  definition
                }
                ... on ExternalReference {
                  source_name
                  url
                  description
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
                    id
                    phase_name
                    x_opencti_order
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
                ... on Opinion {
                  opinion
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
                  killChainPhases {
                    id
                    phase_name
                    x_opencti_order
                  }
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
                  killChainPhases {
                    id
                    phase_name
                    x_opencti_order
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
                ... on Creator {
                  name
                }
                ... on MarkingDefinition {
                  definition
                }
                ... on ExternalReference {
                  source_name
                  url
                  description
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

export default compose(
  inject18n,
  withTheme,
  withStyles(styles),
)(StixDomainObjectTimeline);
