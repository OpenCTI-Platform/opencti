import React from 'react';
import * as R from 'ramda';
import { graphql } from 'react-relay';
import CircularProgress from '@mui/material/CircularProgress';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import { Link } from 'react-router-dom';
import Timeline from '@mui/lab/Timeline';
import TimelineItem from '@mui/lab/TimelineItem';
import TimelineSeparator from '@mui/lab/TimelineSeparator';
import TimelineConnector from '@mui/lab/TimelineConnector';
import TimelineContent from '@mui/lab/TimelineContent';
import TimelineOppositeContent from '@mui/lab/TimelineOppositeContent';
import TimelineDot from '@mui/lab/TimelineDot';
import makeStyles from '@mui/styles/makeStyles';
import ItemIcon from '../../../../components/ItemIcon';
import { useFormatter } from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import { resolveLink } from '../../../../utils/Entity';
import { defaultValue } from '../../../../utils/Graph';
import { convertFilters } from '../../../../utils/ListParameters';
import { itemColor } from '../../../../utils/Colors';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';

const useStyles = makeStyles((theme) => ({
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
}));

const stixCoreObjectsTimelineQuery = graphql`
  query StixCoreObjectsTimelineQuery(
    $types: [String]
    $first: Int
    $orderBy: StixCoreObjectsOrdering
    $orderMode: OrderingMode
    $filters: [StixCoreObjectsFiltering]
  ) {
    stixCoreObjects(
      types: $types
      first: $first
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) {
      edges {
        node {
          id
          entity_type
          created_at
          ... on StixDomainObject {
            created
            modified
          }
          ... on AttackPattern {
            name
            description
          }
          ... on Campaign {
            name
            description
          }
          ... on Note {
            attribute_abstract
          }
          ... on ObservedData {
            first_observed
            last_observed
          }
          ... on Opinion {
            opinion
          }
          ... on Report {
            name
            description
            published
          }
          ... on Grouping {
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
          ... on Note {
            attribute_abstract
            content
          }
          ... on StixCyberObservable {
            observable_value
          }
          createdBy {
            ... on Identity {
              id
              name
              entity_type
            }
          }
          objectMarking {
            edges {
              node {
                id
                definition_type
                definition
                x_opencti_order
                x_opencti_color
              }
            }
          }
        }
      }
    }
  }
`;

const StixCoreObjectsTimeline = ({
  variant,
  height,
  startDate,
  endDate,
  dataSelection,
  parameters = {},
}) => {
  const classes = useStyles();
  const { t, fldt } = useFormatter();
  const renderContent = () => {
    const selection = dataSelection[0];
    let types = ['Stix-Core-Object'];
    if (
      selection.filters.entity_type
      && selection.filters.entity_type.length > 0
    ) {
      if (
        selection.filters.entity_type.filter((o) => o.id === 'all').length === 0
      ) {
        types = selection.filters.entity_type.map((o) => o.id);
      }
    }
    const filters = convertFilters(R.dissoc('entity_type', selection.filters));
    if (startDate) {
      filters.push({
        key: 'created',
        values: [startDate],
        operator: 'gt',
      });
    }
    if (endDate) {
      filters.push({
        key: 'created',
        values: [endDate],
        operator: 'lt',
      });
    }
    const dateAttribute = selection.date_attribute && selection.date_attribute.length > 0
      ? selection.date_attribute
      : 'created_at';
    return (
      <QueryRenderer
        query={stixCoreObjectsTimelineQuery}
        variables={{
          types,
          first: 50,
          orderBy: dateAttribute,
          orderMode: 'desc',
          filters,
        }}
        render={({ props }) => {
          if (
            props
            && props.stixCoreObjects
            && props.stixCoreObjects.edges.length > 0
          ) {
            const stixCoreObjectsEdges = props.stixCoreObjects.edges;
            return (
              <div id="container" className={classes.container}>
                <Timeline position="alternate">
                  {stixCoreObjectsEdges.map((stixCoreObjectEdge) => {
                    const stixCoreObject = stixCoreObjectEdge.node;
                    const link = `${resolveLink(stixCoreObject.entity_type)}/${
                      stixCoreObject.id
                    }`;
                    return (
                      <TimelineItem key={stixCoreObject.id}>
                        <TimelineOppositeContent
                          sx={{ paddingTop: '18px' }}
                          color="text.secondary"
                        >
                          {fldt(stixCoreObject.created)}
                        </TimelineOppositeContent>
                        <TimelineSeparator>
                          <Link to={link}>
                            <TimelineDot
                              sx={{
                                borderColor: itemColor(
                                  stixCoreObject.entity_type,
                                ),
                              }}
                              variant="outlined"
                            >
                              <ItemIcon type={stixCoreObject.entity_type} />
                            </TimelineDot>
                          </Link>
                          <TimelineConnector />
                        </TimelineSeparator>
                        <TimelineContent>
                          <Paper variant="outlined" className={classes.paper}>
                            <Typography variant="h2">
                              {defaultValue(stixCoreObject)}
                            </Typography>
                            <div style={{ marginTop: -5, color: '#a8a8a8' }}>
                              <MarkdownDisplay
                                content={stixCoreObject.description}
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
  };
  return (
    <div style={{ height: height || '100%' }}>
      <Typography
        variant="h4"
        gutterBottom={true}
        style={{
          margin: variant !== 'inLine' ? '0 0 10px 0' : '-10px 0 10px -7px',
        }}
      >
        {parameters.title ?? t('Entities list')}
      </Typography>
      {variant !== 'inLine' ? (
        <Paper classes={{ root: classes.paper }} variant="outlined">
          {renderContent()}
        </Paper>
      ) : (
        renderContent()
      )}
    </div>
  );
};

export default StixCoreObjectsTimeline;
