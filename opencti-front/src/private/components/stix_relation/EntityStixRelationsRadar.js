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
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import { QueryRenderer } from '../../../relay/environment';
import inject18n from '../../../components/i18n';
import Theme from '../../../components/Theme';

const styles = theme => ({
  paper: {
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '30px 0 0 0',
    backgroundColor: theme.palette.paper.background,
    color: theme.palette.text.main,
    borderRadius: 6,
  },
});

const entityStixRelationsRadarStixRelationDistributionQuery = graphql`
    query EntityStixRelationsRadarStixRelationDistributionQuery($fromId: String, $toTypes: [String], $relationType: String, $field: String!, $operation: StatsOperation!) {
        stixRelationsDistribution(fromId: $fromId, toTypes: $toTypes, relationType: $relationType, field: $field, operation: $operation) {
            label,
            value
        }
    }
`;

class EntityStixRelationsRadar extends Component {
  render() {
    const {
      t, classes, entityId, entityType, relationType, field,
    } = this.props;
    const stixRelationsDistributionVariables = {
      fromId: entityId,
      toTypes: entityType ? [entityType] : null,
      relationType,
      field,
      operation: 'count',
    };
    return (
      <div style={{ height: '100%' }}>
        <Typography variant='h4' gutterBottom={true}>
          {t('Distribution:')} {t(`entity_${entityType}`)}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <QueryRenderer
            query={entityStixRelationsRadarStixRelationDistributionQuery}
            variables={stixRelationsDistributionVariables}
            render={({ props }) => {
              if (props && props.stixRelationsDistribution) {
                return (
                  <ResponsiveContainer height={300} width='100%'>
                    <RadarChart outerRadius={110} data={props.stixRelationsDistribution}>
                      <PolarGrid/>
                      <PolarAngleAxis dataKey='label' stroke='#ffffff'/>
                      <PolarRadiusAxis/>
                      <Radar dataKey='value' stroke='#8884d8' fill={Theme.palette.primary.main} fillOpacity={0.6}/>
                    </RadarChart>
                  </ResponsiveContainer>
                );
              }
              return (
                <div> &nbsp; </div>
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
  field: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(EntityStixRelationsRadar);
