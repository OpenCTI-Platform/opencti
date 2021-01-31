import React, { Component } from 'react';
import PropTypes from 'prop-types';
import * as R from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import inject18n from '../../../../components/i18n';
import EntityStixCoreRelationshipsHorizontalBars from '../../common/stix_core_relationships/EntityStixCoreRelationshipsHorizontalBars';
import StixDomainObjectVictimologyMap from '../../common/stix_domain_objects/StixDomainObjectVictimologyMap';
import EntityStixCoreRelationshipsDonut from '../../common/stix_core_relationships/EntityStixCoreRelationshipsDonut';
import EntityStixCoreRelationshipsAreaChart from '../../common/stix_core_relationships/EntityStixCoreRelationshipsAreaChart';
import EntityStixCoreRelationshipsVerticalBars from '../../common/stix_core_relationships/EntityStixCoreRelationshipsVerticalBars';

const styles = () => ({
  container: {
    margin: 0,
  },
});

class ThreatVictimologyAll extends Component {
  render() {
    const {
      t, widget, startDate, endDate,
    } = this.props;
    switch (widget.visualizationType) {
      case 'horizontal-bar':
        return (
          <EntityStixCoreRelationshipsHorizontalBars
            title={`${t('Victimology (countries)')} - ${widget.entity.name}`}
            stixCoreObjectId={widget.entity.id}
            toTypes={['Country']}
            relationshipType="targets"
            field="internal_id"
            startDate={startDate}
            endDate={endDate}
            variant="inline"
          />
        );
      case 'donut':
        return (
          <EntityStixCoreRelationshipsDonut
            title={`${t('Victimology (countries)')} - ${widget.entity.name}`}
            stixCoreObjectId={widget.entity.id}
            toTypes={['Country']}
            relationshipType="targets"
            field="internal_id"
            startDate={startDate}
            endDate={endDate}
            variant="inline"
          />
        );
      case 'map':
        return (
          <StixDomainObjectVictimologyMap
            title={`${t('Victimology (countries)')} - ${widget.entity.name}`}
            stixDomainObjectId={widget.entity.id}
            startDate={startDate}
            endDate={endDate}
            variant="inline"
          />
        );
      case 'area':
        return (
          <EntityStixCoreRelationshipsAreaChart
            title={`${t('Victimology (countries)')} - ${widget.entity.name}`}
            stixCoreObjectId={widget.entity.id}
            toTypes={['Country']}
            relationshipType="targets"
            startDate={startDate}
            endDate={endDate}
            variant="inline"
          />
        );
      case 'vertical-bar':
        return (
          <EntityStixCoreRelationshipsVerticalBars
            title={`${t('Victimology (countries)')} - ${widget.entity.name}`}
            stixCoreObjectId={widget.entity.id}
            toTypes={['Country']}
            relationshipType="targets"
            startDate={startDate}
            endDate={endDate}
            variant="inline"
          />
        );
      default:
        return (
          <div style={{ display: 'table', height: '100%', width: '100%' }}>
            <span
              style={{
                display: 'table-cell',
                verticalAlign: 'middle',
                textAlign: 'center',
              }}
            >
              {t('Not implemented yet.')}
            </span>
          </div>
        );
    }
  }
}

ThreatVictimologyAll.propTypes = {
  startDate: PropTypes.string,
  endDate: PropTypes.string,
  widget: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default R.compose(inject18n, withStyles(styles))(ThreatVictimologyAll);
