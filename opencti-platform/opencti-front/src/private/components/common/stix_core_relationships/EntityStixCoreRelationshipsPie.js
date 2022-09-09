import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql } from 'react-relay';
import { PieChart, Pie, Cell, Legend, ResponsiveContainer } from 'recharts';
import withStyles from '@mui/styles/withStyles';
import CircularProgress from '@mui/material/CircularProgress';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import { SettingsInputComponent } from '@mui/icons-material';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import { itemColor } from '../../../../utils/Colors';
import Security, { EXPLORE_EXUPDATE } from '../../../../utils/Security';

const styles = () => ({
  paper: {
    minHeight: 280,
    height: '100%',
    margin: '10px 0 0 0',
    padding: 0,
    borderRadius: 6,
  },
  paperExplore: {
    height: '100%',
    margin: 0,
    padding: 0,
    borderRadius: 6,
  },
  updateButton: {
    float: 'right',
    margin: '7px 10px 0 0',
  },
});
const RADIAN = Math.PI / 180;
const renderCustomizedLabel = ({
  cx,
  cy,
  midAngle,
  innerRadius,
  outerRadius,
  percent,
}) => {
  const radius = innerRadius + (outerRadius - innerRadius) * 0.5;
  const x = cx + radius * Math.cos(-midAngle * RADIAN);
  const y = cy + radius * Math.sin(-midAngle * RADIAN);

  return (
    <text
      x={x}
      y={y}
      fill="white"
      textAnchor={x > cx ? 'start' : 'end'}
      dominantBaseline="central"
    >
      {`${(percent * 100).toFixed(0)}%`}
    </text>
  );
};

const entityStixCoreRelationshipsPieStixCoreRelationshipDistributionQuery = graphql`
  query EntityStixCoreRelationshipsPieStixCoreRelationshipDistributionQuery(
    $fromId: StixRef!
    $toTypes: [String]
    $relationship_type: String
    $startDate: DateTime
    $endDate: DateTime
    $field: String!
    $operation: StatsOperation!
  ) {
    stixCoreRelationshipsDistribution(
      fromId: $fromId
      toTypes: $toTypes
      relationship_type: $relationship_type
      startDate: $startDate
      endDate: $endDate
      field: $field
      operation: $operation
    ) {
      label
      value
    }
  }
`;

class EntityStixCoreRelationshipsPie extends Component {
  renderContent() {
    const {
      t,
      entityId,
      entityType,
      // eslint-disable-next-line @typescript-eslint/naming-convention
      relationship_type,
      field,
      variant,
      startDate,
      endDate,
    } = this.props;
    const stixCoreRelationshipsDistributionVariables = {
      fromId: entityId,
      toTypes: entityType ? [entityType] : null,
      startDate: startDate || null,
      endDate: endDate || null,
      relationship_type,
      field,
      operation: 'count',
    };
    return (
      <QueryRenderer
        query={
          entityStixCoreRelationshipsPieStixCoreRelationshipDistributionQuery
        }
        variables={stixCoreRelationshipsDistributionVariables}
        render={({ props }) => {
          if (
            props
            && props.stixCoreRelationshipsDistribution
            && props.stixCoreRelationshipsDistribution.length > 0
          ) {
            return (
              <ResponsiveContainer
                height={variant === 'explore' ? '90%' : 280}
                width="100%"
              >
                <PieChart
                  margin={{
                    top: 50,
                    right: 12,
                    bottom: 25,
                    left: 0,
                  }}
                >
                  <Pie
                    data={props.stixCoreRelationshipsDistribution}
                    dataKey="value"
                    nameKey="label"
                    cx="50%"
                    cy="50%"
                    outerRadius={100}
                    fill="#82ca9d"
                    label={renderCustomizedLabel}
                    labelLine={false}
                  >
                    {props.stixCoreRelationshipsDistribution.map(
                      (entry, index) => (
                        <Cell key={index} fill={itemColor(entry.label)} />
                      ),
                    )}
                  </Pie>
                  <Legend
                    verticalAlign="bottom"
                    wrapperStyle={{ paddingTop: 20 }}
                  />
                </PieChart>
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
    const {
      t,
      classes,
      variant,
      title,
      entityType,
      configuration,
      handleOpenConfig,
    } = this.props;
    if (variant === 'explore') {
      return (
        <Paper classes={{ root: classes.paperExplore }} variant="outlined">
          <Typography
            variant="h4"
            gutterBottom={true}
            style={{ float: 'left', padding: '10px 0 0 10px' }}
          >
            {title || `${t('Distribution:')} ${t(`entity_${entityType}`)}`}
          </Typography>
          <Security needs={[EXPLORE_EXUPDATE]}>
            <IconButton
              color="secondary"
              aria-label="Update"
              size="small"
              classes={{ root: classes.updateButton }}
              onClick={handleOpenConfig.bind(this, configuration)}
            >
              <SettingsInputComponent fontSize="inherit" />
            </IconButton>
          </Security>
          <div className="clearfix" />
          {this.renderContent()}
        </Paper>
      );
    }
    return (
      <div style={{ height: '100%' }}>
        <Typography
          variant="h4"
          gutterBottom={true}
          style={{
            margin: variant !== 'inLine' ? '0 0 10px 0' : '-10px 0 10px -7px',
          }}
        >
          {title || `${t('Distribution:')} ${t(`entity_${entityType}`)}`}
        </Typography>
        <Paper classes={{ root: classes.paper }} variant="outlined">
          {this.renderContent()}
        </Paper>
      </div>
    );
  }
}

EntityStixCoreRelationshipsPie.propTypes = {
  variant: PropTypes.string,
  title: PropTypes.string,
  entityId: PropTypes.string,
  relationship_type: PropTypes.string,
  entityType: PropTypes.string,
  startDate: PropTypes.string,
  endDate: PropTypes.string,
  field: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  configuration: PropTypes.object,
  handleOpenConfig: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(EntityStixCoreRelationshipsPie);
