import React, { Component } from 'react';
import PropTypes from 'prop-types';
import * as R from 'ramda';
import withStyles from '@mui/styles/withStyles';
import inject18n from '../../../../components/i18n';
import EntityStixCoreRelationshipsHorizontalBars from '../../common/stix_core_relationships/EntityStixCoreRelationshipsHorizontalBars';
import EntityStixCoreRelationshipsDonut from '../../common/stix_core_relationships/EntityStixCoreRelationshipsDonut';
import EntityStixCoreRelationshipsAreaChart from '../../common/stix_core_relationships/EntityStixCoreRelationshipsAreaChart';
import EntityStixCoreRelationshipsVerticalBars from '../../common/stix_core_relationships/EntityStixCoreRelationshipsVerticalBars';
import EntityStixCoreRelationshipsList from '../../common/stix_core_relationships/EntityStixCoreRelationshipsList';

const styles = () => ({
  container: {
    margin: 0,
  },
});

class ThreatVictimologyAll extends Component {
  render() {
    const { t, startDate, endDate, widget, timeField } = this.props;
    let dateAttribute = 'created_at';
    if (timeField === 'functional') {
      dateAttribute = 'start_time';
    }
    switch (widget.visualizationType) {
      case 'horizontal-bar':
        return (
          <EntityStixCoreRelationshipsHorizontalBars
            title={`${t('Victimology')} - ${widget.entity.name}`}
            stixCoreObjectId={widget.entity.id}
            toTypes={['Sector', 'Country']}
            relationshipType="targets"
            field="internal_id"
            startDate={startDate}
            endDate={endDate}
            dateAttribute={dateAttribute}
            variant="inLine"
          />
        );
      case 'donut':
        return (
          <EntityStixCoreRelationshipsDonut
            title={`${t('Victimology')} - ${widget.entity.name}`}
            entityId={widget.entity.id}
            toTypes={['Sector', 'Country']}
            relationshipType="targets"
            field="internal_id"
            startDate={startDate}
            endDate={endDate}
            dateAttribute={dateAttribute}
            variant="inLine"
          />
        );
      case 'area':
        return (
          <EntityStixCoreRelationshipsAreaChart
            title={`${t('Victimology')} - ${widget.entity.name}`}
            stixCoreObjectId={widget.entity.id}
            toTypes={['Sector', 'Country']}
            relationshipType="targets"
            startDate={startDate}
            endDate={endDate}
            field={dateAttribute}
            variant="inLine"
          />
        );
      case 'vertical-bars':
        return (
          <EntityStixCoreRelationshipsVerticalBars
            title={`${t('Victimology')} - ${widget.entity.name}`}
            stixCoreObjectId={widget.entity.id}
            toTypes={['Sector', 'Country']}
            relationshipType="targets"
            startDate={startDate}
            endDate={endDate}
            field={dateAttribute}
            variant="inLine"
          />
        );
      case 'list':
        return (
          <EntityStixCoreRelationshipsList
            title={`${t('Victimology')} - ${widget.entity.name}`}
            stixCoreObjectId={widget.entity.id}
            toTypes={['Sector', 'Country']}
            relationshipType="targets"
            field="internal_id"
            startDate={startDate}
            endDate={endDate}
            variant="inLine"
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
  timeField: PropTypes.string,
  widget: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default R.compose(inject18n, withStyles(styles))(ThreatVictimologyAll);
