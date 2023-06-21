import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql } from 'react-relay';
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
import { Link } from 'react-router-dom';
import CircularProgress from '@mui/material/CircularProgress';
import { QueryRenderer } from '../../../../relay/environment';
import ItemIcon from '../../../../components/ItemIcon';
import inject18n from '../../../../components/i18n';
import { defaultValue } from '../../../../utils/Graph';
import { resolveLink } from '../../../../utils/Entity';
import { itemColor } from '../../../../utils/Colors';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';

const styles = (theme) => ({
  container: {
    width: '100%',
    height: '100%',
    overflow: 'auto',
  },
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

const stixDomainObjectsTimelineQuery = graphql`
  query StixDomainObjectsTimelineQuery(
    $first: Int
    $types: [String]
    $orderBy: StixDomainObjectsOrdering
    $orderMode: OrderingMode
  ) {
    stixDomainObjects(
      first: $first
      types: $types
      orderBy: $orderBy
      orderMode: $orderMode
    ) {
      edges {
        node {
          id
          entity_type
          created
          modified
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
          ... on Note {
            attribute_abstract
            content
          }
        }
      }
    }
  }
`;

class StixDomainObjectsTimeline extends Component {
  renderContent() {
    const { t, types, fldt, classes } = this.props;
    const stixDomainObjectsVariables = {
      types,
      first: 10,
      orderBy: 'created',
      orderMode: 'desc',
    };
    return (
      <QueryRenderer
        query={stixDomainObjectsTimelineQuery}
        variables={stixDomainObjectsVariables}
        render={({ props }) => {
          if (
            props
            && props.stixDomainObjects
            && props.stixDomainObjects.edges.length > 0
          ) {
            const stixDomainObjectsEdges = props.stixDomainObjects.edges;
            return (
              <div id="container" className={classes.container}>
                <Timeline position="alternate">
                  {stixDomainObjectsEdges.map((stixDomainObjectEdge) => {
                    const stixDomainObject = stixDomainObjectEdge.node;
                    const link = `${resolveLink(
                      stixDomainObject.entity_type,
                    )}/${stixDomainObject.id}`;
                    return (
                      <TimelineItem key={stixDomainObject.id}>
                        <TimelineOppositeContent
                          sx={{ paddingTop: '18px' }}
                          color="text.secondary"
                        >
                          {fldt(stixDomainObject.created)}
                        </TimelineOppositeContent>
                        <TimelineSeparator>
                          <Link to={link}>
                            <TimelineDot
                              sx={{
                                borderColor: itemColor(
                                  stixDomainObject.entity_type,
                                ),
                              }}
                              variant="outlined"
                            >
                              <ItemIcon type={stixDomainObject.entity_type} />
                            </TimelineDot>
                          </Link>
                          <TimelineConnector />
                        </TimelineSeparator>
                        <TimelineContent>
                          <Paper variant="outlined" className={classes.paper}>
                            <Typography variant="h2">
                              {defaultValue(stixDomainObject)}
                            </Typography>
                            <div style={{ marginTop: -5, color: '#a8a8a8' }}>
                              <MarkdownDisplay
                                content={stixDomainObject.description}
                                limit={150}
                              />
                            </div>
                          </Paper>
                        </TimelineContent>
                      </TimelineItem>
                    );
                  })}
                </Timeline>
              </div>
            );
          }
          if (props) {
            return (
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
            );
          }
          return (
            <div style={{ display: 'table', height: '100%', width: '100%' }}>
              <span
                style={{
                  display: 'table-cell',
                  verticalAlign: 'middle',
                  textAlign: 'center',
                }}
              >
                <CircularProgress size={40} thickness={2} />
              </span>
            </div>
          );
        }}
      />
    );
  }

  render() {
    const { t, classes, title, variant } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography
          variant="h4"
          gutterBottom={true}
          style={{
            margin: variant !== 'inLine' ? '-10px 0 5px -7px' : '0 0 10px 0',
          }}
        >
          {title || t('StixDomainObjects timeline')}
        </Typography>
        {variant !== 'inLine' ? (
          <Paper classes={{ root: classes.paper }} variant="outlined">
            {this.renderContent()}
          </Paper>
        ) : (
          this.renderContent()
        )}
      </div>
    );
  }
}

StixDomainObjectsTimeline.propTypes = {
  stixDomainObjectId: PropTypes.string,
  data: PropTypes.object,
  entityLink: PropTypes.string,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixDomainObjectsTimeline);
