import React from 'react';
import * as R from 'ramda';
import { graphql } from 'react-relay';
import CircularProgress from '@mui/material/CircularProgress';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import ListItem from '@mui/material/ListItem';
import { Link } from 'react-router-dom';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import List from '@mui/material/List';
import makeStyles from '@mui/styles/makeStyles';
import StixCoreObjectLabels from './StixCoreObjectLabels';
import ItemIcon from '../../../../components/ItemIcon';
import { useFormatter } from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import { resolveLink } from '../../../../utils/Entity';
import { defaultValue } from '../../../../utils/Graph';
import { convertFilters } from '../../../../utils/ListParameters';
import ItemMarkings from '../../../../components/ItemMarkings';

const useStyles = makeStyles((theme) => ({
  container: {
    width: '100%',
    height: '100%',
    overflow: 'auto',
    paddingBottom: 10,
    marginBottom: 10,
  },
  paper: {
    height: '100%',
    margin: '10px 0 0 0',
    padding: 0,
    borderRadius: 6,
  },
  item: {
    paddingLeft: 10,
    height: 50,
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
  itemIcon: {
    marginRight: 0,
    color: theme.palette.primary.main,
  },
  itemIconDisabled: {
    marginRight: 0,
    color: theme.palette.grey[700],
  },
  parameters: {
    margin: '0 0 20px 0',
    padding: 0,
  },
  filters: {
    float: 'left',
    margin: '-4px 0 0 15px',
  },
  operator: {
    fontFamily: 'Consolas, monaco, monospace',
    backgroundColor: theme.palette.background.accent,
    margin: '0 10px 0 10px',
  },
  export: {
    float: 'right',
    margin: '0 0 0 20px',
  },
  chips: {
    display: 'flex',
    flexWrap: 'wrap',
  },
  chip: {
    margin: theme.spacing(1) / 4,
  },
}));

const stixCoreObjectsListQuery = graphql`
  query StixCoreObjectsListQuery(
    $types: [String]
    $first: Int
    $orderBy: StixCoreObjectsOrdering
    $orderMode: OrderingMode
    $filters: [StixCoreObjectsFiltering]
    $relationship_type: [String]
    $elementId: [String]
  ) {
    stixCoreObjects(
      types: $types
      first: $first
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
      relationship_type: $relationship_type
      elementId: $elementId
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
          ... on Task {
            name
            description
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
          objectLabel {
            edges {
              node {
                id
                value
                color
              }
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

const StixCoreObjectsList = ({
  variant,
  height,
  startDate,
  endDate,
  dataSelection,
  parameters = {},
}) => {
  const classes = useStyles();
  const { t, fsd } = useFormatter();
  const renderContent = () => {
    const selection = dataSelection[0];
    let finalFilters = convertFilters(selection.filters);
    const dataSelectionTypes = R.head(
      finalFilters.filter((n) => n.key === 'entity_type'),
    )?.values || ['Stix-Core-Object'];
    const dataSelectionElementId = R.head(finalFilters.filter((n) => n.key === 'elementId'))?.values || null;
    const dataSelectionRelationshipType = R.head(finalFilters.filter((n) => n.key === 'relationship_type'))
      ?.values || null;
    finalFilters = finalFilters.filter(
      (n) => !['entity_type', 'elementId', 'relationship_type'].includes(n.key),
    );
    const dateAttribute = selection.date_attribute && selection.date_attribute.length > 0
      ? selection.date_attribute
      : 'created_at';
    if (startDate) {
      finalFilters.push({
        key: dateAttribute,
        values: [startDate],
        operator: 'gt',
      });
    }
    if (endDate) {
      finalFilters.push({
        key: dateAttribute,
        values: [endDate],
        operator: 'lt',
      });
    }
    return (
      <QueryRenderer
        query={stixCoreObjectsListQuery}
        variables={{
          types: dataSelectionTypes,
          first: selection.number ?? 10,
          orderBy: dateAttribute,
          orderMode: 'desc',
          filters: finalFilters,
          elementId: dataSelectionElementId,
          relationship_type: dataSelectionRelationshipType,
        }}
        render={({ props }) => {
          if (
            props
            && props.stixCoreObjects
            && props.stixCoreObjects.edges.length > 0
          ) {
            const data = props.stixCoreObjects.edges;
            return (
              <div id="container" className={classes.container}>
                <List style={{ marginTop: -10 }}>
                  {data.map((stixCoreObjectEdge) => {
                    const stixCoreObject = stixCoreObjectEdge.node;
                    return (
                      <ListItem
                        key={stixCoreObject.id}
                        classes={{ root: classes.item }}
                        divider={true}
                        button={true}
                        component={Link}
                        to={`${resolveLink(stixCoreObject.entity_type)}/${
                          stixCoreObject.id
                        }`}
                      >
                        <ListItemIcon>
                          <ItemIcon type={stixCoreObject.entity_type} />
                        </ListItemIcon>
                        <ListItemText
                          primary={
                            <>
                              <div
                                className={classes.bodyItem}
                                style={{ width: '30%' }}
                              >
                                {defaultValue(stixCoreObject)}
                              </div>
                              <div
                                className={classes.bodyItem}
                                style={{ width: '15%' }}
                              >
                                {fsd(stixCoreObject[dateAttribute])}
                              </div>
                              <div
                                className={classes.bodyItem}
                                style={{ width: '15%' }}
                              >
                                {R.pathOr(
                                  '',
                                  ['createdBy', 'name'],
                                  stixCoreObject,
                                )}
                              </div>
                              <div
                                className={classes.bodyItem}
                                style={{ width: '15%' }}
                              >
                                <StixCoreObjectLabels
                                  variant="inList"
                                  labels={stixCoreObject.objectLabel}
                                />
                              </div>
                              <div
                                className={classes.bodyItem}
                                style={{ width: '15%' }}
                              >
                                <ItemMarkings
                                  variant="inList"
                                  markingDefinitionsEdges={
                                    stixCoreObject.objectMarking.edges
                                  }
                                  limit={1}
                                />
                              </div>
                            </>
                          }
                        />
                      </ListItem>
                    );
                  })}
                </List>
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
          whiteSpace: 'nowrap',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
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

export default StixCoreObjectsList;
