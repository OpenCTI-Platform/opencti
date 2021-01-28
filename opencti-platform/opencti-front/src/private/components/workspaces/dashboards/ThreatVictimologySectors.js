import React, { Component } from 'react';
import PropTypes from 'prop-types';
import * as R from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import inject18n from '../../../../components/i18n';
import EntityStixCoreRelationshipsDonut from '../../common/stix_core_relationships/EntityStixCoreRelationshipsDonut';

const styles = () => ({
  container: {
    margin: 0,
  },
});

class ThreatVictimologyAll extends Component {
  render() {
    const {
      t, startDate, endDate, widget,
    } = this.props;
    switch (widget.visualizationType) {
      case 'donut':
        return (
          <EntityStixCoreRelationshipsDonut
            title={`${t('Victimology')} - ${widget.entity.name}`}
            entityId={widget.entity.id}
            entityType={widget.entity.type}
            relationshipType="targets"
            field="name"
            startDate={startDate}
            endDate={endDate}
          />
        );
      default:
        return 'Not implemented yet';
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
