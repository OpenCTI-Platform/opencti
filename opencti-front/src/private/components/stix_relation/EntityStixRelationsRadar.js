import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import ResponsiveContainer from 'recharts/lib/component/ResponsiveContainer';
import RadarChart from 'recharts/lib/chart/RadarChart';
import PolarGrid from 'recharts/lib/polar/PolarGrid';
import PolarAngleAxis from 'recharts/lib/polar/PolarAngleAxis';
import PolarRadiusAxis from 'recharts/lib/polar/PolarRadiusAxis';
import Radar from 'recharts/lib/polar/Radar';
import { withStyles } from '@material-ui/core/styles';
import CircularProgress from '@material-ui/core/CircularProgress';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import { QueryRenderer } from '../../../relay/environment';
import inject18n from '../../../components/i18n';
import Theme from '../../../components/Theme';

const styles = theme => ({
  paper: {
    minHeight: 300,
    height: '100%',
    margin: '10px 0 0 0',
    backgroundColor: theme.palette.paper.background,
    color: theme.palette.text.main,
    borderRadius: 6,
  },
});

const entityStixRelationsRadarStixRelationDistributionQuery = graphql`
  query EntityStixRelationsRadarStixRelationDistributionQuery(
    $fromId: String
    $toTypes: [String]
    $relationType: String
    $resolveInferences: Boolean
    $resolveRelationType: String
    $resolveRelationRole: String
    $resolveRelationToTypes: [String]
    $resolveViaTypes: [EntityRelation]
    $field: String!
    $operation: StatsOperation!
  ) {
    stixRelationsDistribution(
      fromId: $fromId
      toTypes: $toTypes
      relationType: $relationType
      resolveInferences: $resolveInferences
      resolveRelationType: $resolveRelationType
      resolveRelationRole: $resolveRelationRole
      resolveRelationToTypes: $resolveRelationToTypes
      resolveViaTypes: $resolveViaTypes
      field: $field
      operation: $operation
    ) {
      label
      value
    }
  }
`;

class EntityStixRelationsRadar extends Component {
  render() {
    const {
      t,
      classes,
      entityId,
      entityType,
      relationType,
      field,
      resolveInferences,
      resolveRelationType,
      resolveRelationRole,
      resolveRelationToTypes,
      resolveViaTypes,
    } = this.props;
    const stixRelationsDistributionVariables = {
      resolveInferences,
      resolveRelationType,
      resolveRelationRole,
      resolveRelationToTypes,
      resolveViaTypes,
      fromId: entityId,
      toTypes: entityType ? [entityType] : null,
      relationType,
      field,
      operation: 'count',
    };
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Distribution:')} {t(`entity_${entityType}`)}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <QueryRenderer
            query={entityStixRelationsRadarStixRelationDistributionQuery}
            variables={stixRelationsDistributionVariables}
            render={({ props }) => {
              if (
                props
                && props.stixRelationsDistribution
                && props.stixRelationsDistribution.length > 0
              ) {
                return (
                  <ResponsiveContainer height={300} width="100%">
                    <RadarChart
                      outerRadius={110}
                      data={props.stixRelationsDistribution}
                    >
                      <PolarGrid />
                      <PolarAngleAxis dataKey="label" stroke="#ffffff" />
                      <PolarRadiusAxis />
                      <Radar
                        dataKey="value"
                        stroke="#8884d8"
                        fill={Theme.palette.primary.main}
                        fillOpacity={0.6}
                      />
                    </RadarChart>
                  </ResponsiveContainer>
                );
              }
              if (props) {
                return (
                  <div
                    style={{ display: 'table', height: '100%', width: '100%' }}
                  >
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
                <div
                  style={{ display: 'table', height: '100%', width: '100%' }}
                >
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
        </Paper>
      </div>
    );
  }
}

EntityStixRelationsRadar.propTypes = {
  entityId: PropTypes.string,
  relationType: PropTypes.string,
  entityType: PropTypes.string,
  resolveInferences: PropTypes.bool,
  resolveRelationType: PropTypes.string,
  resolveRelationRole: PropTypes.string,
  resolveRelationToTypes: PropTypes.array,
  resolveViaTypes: PropTypes.array,
  field: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(EntityStixRelationsRadar);
