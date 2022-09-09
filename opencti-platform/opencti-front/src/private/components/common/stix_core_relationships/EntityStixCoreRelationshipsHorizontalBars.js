import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import withTheme from '@mui/styles/withTheme';
import CircularProgress from '@mui/material/CircularProgress';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Chart from 'react-apexcharts';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import { itemColor } from '../../../../utils/Colors';
import { horizontalBarsChartOptions } from '../../../../utils/Charts';
import { simpleNumberFormat } from '../../../../utils/Number';

const styles = () => ({
  paper: {
    height: '100%',
    margin: '10px 0 0 0',
    padding: 0,
    borderRadius: 6,
  },
});

const entityStixCoreRelationshipsHorizontalBarsDistributionQuery = graphql`
  query EntityStixCoreRelationshipsHorizontalBarsDistributionQuery(
    $fromId: StixRef
    $relationship_type: String!
    $toTypes: [String]
    $isTo: Boolean
    $field: String!
    $operation: StatsOperation!
    $limit: Int
    $startDate: DateTime
    $endDate: DateTime
    $dateAttribute: String
  ) {
    stixCoreRelationshipsDistribution(
      fromId: $fromId
      relationship_type: $relationship_type
      toTypes: $toTypes
      isTo: $isTo
      field: $field
      operation: $operation
      limit: $limit
      startDate: $startDate
      endDate: $endDate
      dateAttribute: $dateAttribute
    ) {
      label
      value
      entity {
        ... on BasicObject {
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
      }
    }
  }
`;

class EntityStixCoreRelationshipsHorizontalBars extends Component {
  renderContent() {
    const {
      t,
      stixCoreObjectId,
      relationshipType,
      toTypes,
      field,
      isTo,
      startDate,
      endDate,
      theme,
      dateAttribute,
      seriesName,
    } = this.props;
    const stixCoreRelationshipsDistributionVariables = {
      fromId: stixCoreObjectId,
      relationship_type: relationshipType,
      toTypes,
      field: field || 'entity_type',
      startDate: startDate || null,
      endDate: endDate || null,
      dateAttribute,
      limit: 10,
      operation: 'count',
      isTo: isTo || false,
    };
    return (
      <QueryRenderer
        query={entityStixCoreRelationshipsHorizontalBarsDistributionQuery}
        variables={stixCoreRelationshipsDistributionVariables}
        render={({ props }) => {
          if (
            props
            && props.stixCoreRelationshipsDistribution
            && props.stixCoreRelationshipsDistribution.length > 0
          ) {
            const data = props.stixCoreRelationshipsDistribution.map((n) => ({
              x:
                // eslint-disable-next-line no-nested-ternary
                field === 'internal_id'
                  ? n.entity.name
                  : field === 'entity_type'
                    ? t(`entity_${n.label}`)
                    : n.label,
              y: n.value,
              fillColor:
                field === 'internal_id'
                  ? itemColor(n.entity.entity_type)
                  : itemColor(n.label),
            }));
            const chartData = [
              {
                name: seriesName || t('Number of relationships'),
                data,
              },
            ];
            return (
              <Chart
                options={horizontalBarsChartOptions(
                  theme,
                  true,
                  simpleNumberFormat,
                )}
                series={chartData}
                type="bar"
                width="100%"
                height="100%"
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
  }

  render() {
    const { t, classes, title, variant } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography
          variant={variant === 'inEntity' ? 'h3' : 'h4'}
          gutterBottom={true}
          style={{
            margin:
              // eslint-disable-next-line no-nested-ternary
              variant === 'inEntity'
                ? 0
                : variant !== 'inLine'
                  ? '0 0 10px 0'
                  : '-10px 0 10px -7px',
          }}
        >
          {title || t('StixDomainObjects distribution')}
        </Typography>
        {variant === 'inLine' || variant === 'inEntity' ? (
          this.renderContent()
        ) : (
          <Paper classes={{ root: classes.paper }} variant="outlined">
            {this.renderContent()}
          </Paper>
        )}
      </div>
    );
  }
}

EntityStixCoreRelationshipsHorizontalBars.propTypes = {
  stixCoreObjectId: PropTypes.string,
  relationshipType: PropTypes.string,
  toTypes: PropTypes.array,
  title: PropTypes.string,
  field: PropTypes.string,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  isTo: PropTypes.bool,
  variant: PropTypes.string,
  startDate: PropTypes.string,
  endDate: PropTypes.string,
  dateAttribute: PropTypes.string,
  seriesName: PropTypes.string,
};

export default compose(
  inject18n,
  withTheme,
  withStyles(styles),
)(EntityStixCoreRelationshipsHorizontalBars);
