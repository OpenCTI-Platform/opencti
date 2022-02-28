import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { graphql } from 'react-relay';
import Chart from 'react-apexcharts';
import withTheme from '@mui/styles/withTheme';
import withStyles from '@mui/styles/withStyles';
import CircularProgress from '@mui/material/CircularProgress';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
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

const stixCoreRelationshipsHorizontalBarsDistributionQuery = graphql`
  query StixCoreRelationshipsHorizontalBarsDistributionQuery(
    $relationship_type: String!
    $toTypes: [String]
    $field: String!
    $operation: StatsOperation!
    $startDate: DateTime
    $endDate: DateTime
    $dateAttribute: String
    $limit: Int
  ) {
    stixCoreRelationshipsDistribution(
      relationship_type: $relationship_type
      toTypes: $toTypes
      field: $field
      operation: $operation
      startDate: $startDate
      endDate: $endDate
      dateAttribute: $dateAttribute
      limit: $limit
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

class StixCoreRelationshipsHorizontalBars extends Component {
  renderContent() {
    const {
      t,
      stixCoreObjectId,
      relationshipType,
      toTypes,
      field,
      startDate,
      endDate,
      dateAttribute,
      theme,
    } = this.props;
    const stixDomainObjectsDistributionVariables = {
      fromId: stixCoreObjectId,
      relationship_type: relationshipType,
      toTypes,
      field: field || 'entity_type',
      operation: 'count',
      startDate,
      endDate,
      dateAttribute,
      limit: 10,
    };
    return (
      <QueryRenderer
        query={stixCoreRelationshipsHorizontalBarsDistributionQuery}
        variables={stixDomainObjectsDistributionVariables}
        render={({ props }) => {
          if (
            props
            && props.stixCoreRelationshipsDistribution
            && props.stixCoreRelationshipsDistribution.length > 0
          ) {
            const data = props.stixCoreRelationshipsDistribution.map((n) => ({
              x: n.entity.name,
              y: n.value,
              fillColor: itemColor(n.entity.entity_type),
            }));
            const chartData = [{ name: t('Number of relationships'), data }];
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
    const { t, classes, title, variant, height } = this.props;
    return (
      <div style={{ height: height || '100%' }}>
        <Typography
          variant="h4"
          gutterBottom={true}
          style={{
            margin: variant !== 'inLine' ? '0 0 10px 0' : '-10px 0 0 -7px',
          }}
        >
          {title || t('StixCoreRelationships distribution')}
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

StixCoreRelationshipsHorizontalBars.propTypes = {
  relationshipType: PropTypes.string,
  toTypes: PropTypes.array,
  title: PropTypes.string,
  field: PropTypes.string,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  height: PropTypes.number,
  startDate: PropTypes.string,
  endDate: PropTypes.string,
  dateAttribute: PropTypes.string,
  variant: PropTypes.string,
};

export default R.compose(
  inject18n,
  withTheme,
  withStyles(styles),
)(StixCoreRelationshipsHorizontalBars);
