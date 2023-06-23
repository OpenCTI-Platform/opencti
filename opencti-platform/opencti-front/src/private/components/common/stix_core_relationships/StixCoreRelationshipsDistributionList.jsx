import React from 'react';
import { graphql } from 'react-relay';
import CircularProgress from '@mui/material/CircularProgress';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import * as R from 'ramda';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import { Link } from 'react-router-dom';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { QueryRenderer } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import { convertFilters } from '../../../../utils/ListParameters';
import { defaultValue } from '../../../../utils/Graph';
import { resolveLink } from '../../../../utils/Entity';
import ItemIcon from '../../../../components/ItemIcon';
import useGranted, {
  SETTINGS_SETACCESSES,
} from '../../../../utils/hooks/useGranted';

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
    height: 50,
    minHeight: 50,
    maxHeight: 50,
    paddingRight: 0,
  },
  itemText: {
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
  itemIcon: {
    marginRight: 0,
    color: theme.palette.primary.main,
  },
}));

const inlineStyles = {
  itemNumber: {
    float: 'right',
    marginRight: 20,
    fontSize: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
};

const stixCoreRelationshipsDistributionListDistributionQuery = graphql`
  query StixCoreRelationshipsDistributionListDistributionQuery(
    $field: String!
    $operation: StatsOperation!
    $startDate: DateTime
    $endDate: DateTime
    $dateAttribute: String
    $isTo: Boolean
    $limit: Int
    $elementId: [String]
    $elementWithTargetTypes: [String]
    $fromId: [String]
    $fromRole: String
    $fromTypes: [String]
    $toId: [String]
    $toRole: String
    $toTypes: [String]
    $relationship_type: [String]
    $confidences: [Int]
    $search: String
    $filters: [StixCoreRelationshipsFiltering]
    $filterMode: FilterMode
    $dynamicFrom: [StixCoreObjectsFiltering]
    $dynamicTo: [StixCoreObjectsFiltering]
  ) {
    stixCoreRelationshipsDistribution(
      field: $field
      operation: $operation
      startDate: $startDate
      endDate: $endDate
      dateAttribute: $dateAttribute
      isTo: $isTo
      limit: $limit
      elementId: $elementId
      elementWithTargetTypes: $elementWithTargetTypes
      fromId: $fromId
      fromRole: $fromRole
      fromTypes: $fromTypes
      toId: $toId
      toRole: $toRole
      toTypes: $toTypes
      relationship_type: $relationship_type
      confidences: $confidences
      search: $search
      filters: $filters
      filterMode: $filterMode
      dynamicFrom: $dynamicFrom
      dynamicTo: $dynamicTo
    ) {
      label
      value
      entity {
        ... on BasicObject {
          id
          entity_type
        }
        ... on BasicRelationship {
          id
          entity_type
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
        ... on Report {
          name
        }
        ... on StixCyberObservable {
          observable_value
        }
        ... on MarkingDefinition {
          definition_type
          definition
        }
        ... on Creator {
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
      }
    }
  }
`;

const StixCoreRelationshipsDistributionList = ({
  title,
  variant,
  height,
  stixCoreObjectId,
  relationshipType,
  toTypes,
  field,
  startDate,
  endDate,
  dateAttribute,
  dataSelection,
  parameters = {},
}) => {
  const classes = useStyles();
  const { t, n } = useFormatter();
  const hasSetAccess = useGranted([SETTINGS_SETACCESSES]);
  const renderContent = () => {
    let finalFilters = [];
    let selection = {};
    let dataSelectionRelationshipType = null;
    let dataSelectionFromId = null;
    let dataSelectionToId = null;
    let dataSelectionFromTypes = null;
    let dataSelectionToTypes = null;
    if (dataSelection) {
      // eslint-disable-next-line prefer-destructuring
      selection = dataSelection[0];
      finalFilters = convertFilters(selection.filters);
      dataSelectionRelationshipType = R.head(finalFilters.filter((o) => o.key === 'relationship_type'))
        ?.values || null;
      dataSelectionFromId = R.head(finalFilters.filter((o) => o.key === 'fromId'))?.values || null;
      dataSelectionToId = R.head(finalFilters.filter((o) => o.key === 'toId'))?.values || null;
      dataSelectionFromTypes = R.head(finalFilters.filter((o) => o.key === 'fromTypes'))?.values
        || null;
      dataSelectionToTypes = R.head(finalFilters.filter((o) => o.key === 'toTypes'))?.values || null;
      finalFilters = finalFilters.filter(
        (o) => ![
          'relationship_type',
          'fromId',
          'toId',
          'fromTypes',
          'toTypes',
        ].includes(o.key),
      );
    }
    const finalField = selection.attribute || field || 'entity_type';
    const variables = {
      fromId: dataSelectionFromId || stixCoreObjectId,
      toId: dataSelectionToId,
      relationship_type: dataSelectionRelationshipType || relationshipType,
      fromTypes: dataSelectionFromTypes,
      toTypes: dataSelectionToTypes || toTypes,
      field: finalField,
      operation: 'count',
      startDate,
      endDate,
      dateAttribute,
      limit: selection.number ?? 10,
      filters: finalFilters,
      isTo: selection.isTo,
      dynamicFrom: convertFilters(selection.dynamicFrom),
      dynamicTo: convertFilters(selection.dynamicTo),
    };
    return (
      <QueryRenderer
        query={stixCoreRelationshipsDistributionListDistributionQuery}
        variables={variables}
        render={({ props }) => {
          if (
            props
            && props.stixCoreRelationshipsDistribution
            && props.stixCoreRelationshipsDistribution.length > 0
          ) {
            const data = props.stixCoreRelationshipsDistribution.map((o) => ({
              label:
                finalField === 'internal_id' ? defaultValue(o.entity) : o.label,
              value: o.value,
              id: finalField === 'internal_id' ? o.entity.id : null,
              type:
                finalField === 'internal_id' ? o.entity.entity_type : o.label,
            }));
            return (
              <div id="container" className={classes.container}>
                <List style={{ marginTop: -10 }}>
                  {data.map((entry) => {
                    // eslint-disable-next-line no-nested-ternary
                    const link = entry.type === 'User' && !hasSetAccess
                      ? null
                      : entry.id
                        ? `${resolveLink(entry.type)}/${entry.id}`
                        : null;
                    return (
                      <ListItem
                        key={entry.label}
                        dense={true}
                        button={!!link}
                        classes={{ root: classes.item }}
                        divider={true}
                        component={link ? Link : null}
                        to={link || null}
                      >
                        <ListItemIcon>
                          <ItemIcon type={entry.type} />
                        </ListItemIcon>
                        <ListItemText
                          primary={
                            <div className={classes.itemText}>
                              {entry.label}
                            </div>
                          }
                        />
                        <div style={inlineStyles.itemNumber}>
                          {n(entry.value)}
                        </div>
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
        }}
      >
        {parameters.title || title || t('Relationships distribution')}
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

export default StixCoreRelationshipsDistributionList;
