import React from 'react';
import * as R from 'ramda';
import { graphql } from 'react-relay';
import CircularProgress from '@mui/material/CircularProgress';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import { useTheme } from '@mui/styles';
import * as PropTypes from 'prop-types';
import { QueryRenderer } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import { donutChartOptions } from '../../../../utils/Charts';
import { defaultValue } from '../../../../utils/Graph';
import Chart from '../charts/Chart';

const useStyles = makeStyles(() => ({
  paper: {
    height: '100%',
    margin: '10px 0 0 0',
    padding: 0,
    borderRadius: 6,
  },
}));

const stixCoreObjectsDonutDistributionQuery = graphql`
  query StixCoreObjectsDonutDistributionQuery(
    $objectId: [String]
    $relationship_type: [String]
    $toTypes: [String]
    $elementWithTargetTypes: [String]
    $field: String!
    $startDate: DateTime
    $endDate: DateTime
    $dateAttribute: String
    $operation: StatsOperation!
    $limit: Int
    $order: String
    $types: [String]
    $filters: FilterGroup
    $search: String
  ) {
    stixCoreObjectsDistribution(
      objectId: $objectId
      relationship_type: $relationship_type
      toTypes: $toTypes
      elementWithTargetTypes: $elementWithTargetTypes
      field: $field
      startDate: $startDate
      endDate: $endDate
      dateAttribute: $dateAttribute
      operation: $operation
      limit: $limit
      order: $order
      types: $types
      filters: $filters
      search: $search
    ) {
      label
      value
      entity {
        ... on BasicObject {
          entity_type
        }
        ... on BasicRelationship {
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
        ... on MarkingDefinition {
          definition_type
          definition
          x_opencti_color
        }
        ... on KillChainPhase {
          kill_chain_name
          phase_name
        }
        ... on Creator {
          name
        }
        ... on Label {
          value
          color
        }
      }
    }
  }
`;

const StixCoreObjectsDonut = ({
  variant,
  height,
  startDate,
  endDate,
  dataSelection,
  parameters = {},
  withExportPopover = false,
  isReadOnly = false,
}) => {
  const classes = useStyles();
  const theme = useTheme();
  const { t } = useFormatter();
  const renderContent = () => {
    const selection = dataSelection[0];
    let finalFiltersContent = selection.filters.filters;
    const dataSelectionTypes = R.head(
      finalFiltersContent.filter((n) => n.key === 'entity_type'),
    )?.values || ['Stix-Core-Object'];
    const dataSelectionObjectId = R.head(finalFiltersContent.filter((n) => n.key === 'elementId'))?.values || null;
    const dataSelectionRelationshipType = R.head(finalFiltersContent.filter((n) => n.key === 'relationship_type'))
      ?.values || null;
    const dataSelectionToTypes = R.head(finalFiltersContent.filter((n) => n.key === 'toTypes'))?.values || null;
    const dataSelectionElementWithTargetTypes = R.head(finalFiltersContent.filter((n) => n.key === 'elementWithTargetTypes'))
      ?.values || null;
    finalFiltersContent = finalFiltersContent.filter(
      (n) => ![
        'entity_type',
        'elementId',
        'relationship_type',
        'toTypes',
        'elementWithTargetTypes',
      ].includes(n.key),
    );
    const variables = {
      objectId: Array.isArray(dataSelectionObjectId)
        ? R.head(dataSelectionObjectId)
        : dataSelectionObjectId,
      relationship_type: dataSelectionRelationshipType,
      types: dataSelectionTypes,
      field: selection.attribute,
      operation: 'count',
      startDate,
      endDate,
      dateAttribute:
        selection.date_attribute && selection.date_attribute.length > 0
          ? selection.date_attribute
          : 'created_at',
      filters: {
        ...selection.filters,
        filters: finalFiltersContent,
      },
      limit: selection.number ?? 10,
    };
    if (dataSelectionToTypes && dataSelectionToTypes.length > 0) {
      variables.toTypes = dataSelectionToTypes;
    }
    if (
      dataSelectionElementWithTargetTypes
      && dataSelectionElementWithTargetTypes.length > 0
    ) {
      variables.elementWithTargetTypes = dataSelectionElementWithTargetTypes;
    }
    return (
      <QueryRenderer
        query={stixCoreObjectsDonutDistributionQuery}
        variables={variables}
        render={({ props }) => {
          if (
            props
            && props.stixCoreObjectsDistribution
            && props.stixCoreObjectsDistribution.length > 0
          ) {
            const data = props.stixCoreObjectsDistribution;
            const chartData = data.map((n) => n.value);
            // eslint-disable-next-line no-nested-ternary
            const labels = data.map((n) => (selection.attribute.endsWith('_id')
              ? defaultValue(n.entity)
              : selection.attribute === 'entity_type'
                ? t(`entity_${n.label}`)
                : n.label));
            let chartColors = [];
            if (data.at(0)?.entity?.color) {
              chartColors = data.map((n) => (theme.palette.mode === 'light' && n.entity.color === '#ffffff'
                ? '#000000'
                : n.entity.color));
            }
            if (data.at(0)?.entity?.x_opencti_color) {
              chartColors = data.map((n) => (theme.palette.mode === 'light'
                && n.entity.x_opencti_color === '#ffffff'
                ? '#000000'
                : n.entity.x_opencti_color));
            }
            return (
              <Chart
                options={donutChartOptions(
                  theme,
                  labels,
                  'bottom',
                  false,
                  chartColors,
                )}
                series={chartData}
                type="donut"
                width="100%"
                height="100%"
                withExportPopover={withExportPopover}
                isReadOnly={isReadOnly}
              />
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
        variant={variant === 'inEntity' ? 'h3' : 'h4'}
        gutterBottom={true}
        style={{
          margin: variant !== 'inLine' ? '0 0 10px 0' : '-10px 0 10px -7px',
          whiteSpace: 'nowrap',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
        }}
      >
        {parameters.title || t('Distribution of entities')}
      </Typography>
      {variant === 'inLine' || variant === 'inEntity' ? (
        renderContent()
      ) : (
        <Paper classes={{ root: classes.paper }} variant="outlined">
          {renderContent()}
        </Paper>
      )}
    </div>
  );
};

StixCoreObjectsDonut.propTypes = {
  variant: PropTypes.string,
  height: PropTypes.number,
  startDate: PropTypes.string,
  endDate: PropTypes.string,
  dataSelection: PropTypes.array,
  parameters: PropTypes.object,
};

export default StixCoreObjectsDonut;
