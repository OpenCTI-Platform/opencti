import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  assoc, compose, head, last, map, pluck, filter,
} from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import CircularProgress from '@material-ui/core/CircularProgress';
import Typography from '@material-ui/core/Typography';
import inject18n from '../../../../components/i18n';
import LocationMiniMapTargets from './LocationMiniMapTargets';
import { QueryRenderer } from '../../../../relay/environment';
import { computeLevel } from '../../../../utils/Number';
import { dashboardStixCoreRelationshipsDistributionQuery } from '../../Dashboard';

const styles = () => ({
  paper: {
    margin: '10px 0 0 0',
    padding: 0,
    borderRadius: 6,
  },
});

class GlobalVictimologyMap extends Component {
  render() {
    const {
      t, title, startDate, endDate,
    } = this.props;
    return (
      <div style={{ height: '100%', paddingBottom: 10 }}>
        <Typography
          variant="h4"
          gutterBottom={true}
          style={{ marginBottom: 10 }}
        >
          {title || t('Victimology map')}
        </Typography>
        <QueryRenderer
          query={dashboardStixCoreRelationshipsDistributionQuery}
          variables={{
            field: 'internal_id',
            operation: 'count',
            relationship_type: 'targets',
            toTypes: ['Country', 'City'],
            startDate,
            endDate,
            dateAttribute: 'created_at',
            limit: 20,
          }}
          render={({ props }) => {
            if (props && props.stixCoreRelationshipsDistribution) {
              const values = pluck(
                'value',
                props.stixCoreRelationshipsDistribution,
              );
              const countries = map(
                (x) => assoc(
                  'level',
                  computeLevel(x.value, last(values), head(values) + 1),
                  x.entity,
                ),
                filter(
                  (n) => n.entity.entity_type === 'Country',
                  props.stixCoreRelationshipsDistribution,
                ),
              );
              const cities = map(
                (x) => x.entity,
                filter(
                  (n) => n.entity.entity_type === 'City',
                  props.stixCoreRelationshipsDistribution,
                ),
              );
              return (
                <LocationMiniMapTargets
                  center={[48.8566969, 2.3514616]}
                  countries={countries}
                  cities={cities}
                  zoom={2}
                />
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
      </div>
    );
  }
}

GlobalVictimologyMap.propTypes = {
  classes: PropTypes.object,
  title: PropTypes.string,
  t: PropTypes.func,
  startDate: PropTypes.string,
  endDate: PropTypes.string,
};

export default compose(inject18n, withStyles(styles))(GlobalVictimologyMap);
