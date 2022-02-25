import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, map, assoc } from 'ramda';
import { graphql } from 'react-relay';
import {
  BarChart,
  XAxis,
  YAxis,
  Cell,
  CartesianGrid,
  Bar,
  ResponsiveContainer,
  Tooltip,
} from 'recharts';
import withTheme from '@mui/styles/withTheme';
import withStyles from '@mui/styles/withStyles';
import CircularProgress from '@mui/material/CircularProgress';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import { itemColor } from '../../../../utils/Colors';
import { truncate } from '../../../../utils/String';

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

const tickFormatter = (title) => truncate(title.replace(/\[(.*?)\]/gi, ''), 100);

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
            const data = map(
              (n) => assoc(
                'label',
                `[${t(`entity_${n.entity.entity_type}`)}] ${n.entity.name}`,
                n,
              ),
              props.stixCoreRelationshipsDistribution,
            );
            return (
              <ResponsiveContainer height="100%" width="100%">
                <BarChart
                  layout="vertical"
                  data={data}
                  margin={{
                    top: 20,
                    right: 20,
                    bottom: 20,
                    left: 12,
                  }}
                >
                  <XAxis
                    type="number"
                    dataKey="value"
                    stroke={theme.palette.text.primary}
                    allowDecimals={false}
                  />
                  <YAxis
                    stroke={theme.palette.text.primary}
                    dataKey="label"
                    type="category"
                    angle={-30}
                    textAnchor="end"
                    tickFormatter={tickFormatter}
                  />
                  <CartesianGrid
                    strokeDasharray="2 2"
                    stroke={theme.palette.action.grid}
                  />
                  <Tooltip
                    cursor={{
                      fill: 'rgba(0, 0, 0, 0.2)',
                      stroke: 'rgba(0, 0, 0, 0.2)',
                      strokeWidth: 2,
                    }}
                    contentStyle={{
                      backgroundColor: 'rgba(255, 255, 255, 0.1)',
                      fontSize: 12,
                      borderRadius: 10,
                    }}
                  />
                  <Bar
                    fill={theme.palette.primary.main}
                    dataKey="value"
                    barSize={15}
                  >
                    {props.stixCoreRelationshipsDistribution.map(
                      (entry, index) => (
                        <Cell
                          key={`cell-${index}`}
                          fill={itemColor(entry.entity.entity_type)}
                        />
                      ),
                    )}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
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
        <Typography variant="h4" gutterBottom={true}>
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

export default compose(
  inject18n,
  withTheme,
  withStyles(styles),
)(StixCoreRelationshipsHorizontalBars);
