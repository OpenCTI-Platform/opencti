import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose, propOr, pathOr } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import inject18n from '../../../components/i18n';
import EntityStixCoreRelationshipsTable from '../common/stix_core_relationships/EntityStixCoreRelationshipsTable';

const styles = () => ({
  container: {
    margin: 0,
  },
});

class AttackPatternsDistribution extends Component {
  render() {
    const {
      configuration, handleOpenConfig, startDate, endDate,
    } = this.props;
    switch (configuration.graph_type) {
      case 'table':
        return (
          <EntityStixCoreRelationshipsTable
            variant="explore"
            configuration={configuration}
            handleOpenConfig={handleOpenConfig.bind(this)}
            title={propOr('Widget', 'title', configuration)}
            entityId={pathOr(null, ['entity', 'id'], configuration)}
            entityType="Attack-Pattern"
            relationshipType="uses"
            field="name"
            startDate={startDate}
            endDate={endDate}
          />
        );
      default:
        return (
          <EntityStixCoreRelationshipsTable
            variant="explore"
            configuration={configuration}
            handleOpenConfig={handleOpenConfig.bind(this)}
            title={propOr('Widget', 'title', configuration)}
            entityId={pathOr(null, ['entity', 'id'], configuration)}
            entityType="Attack-Pattern"
            relationshipType="uses"
            field="name"
            startDate={startDate}
            endDate={endDate}
          />
        );
    }
  }
}

AttackPatternsDistribution.propTypes = {
  configuration: PropTypes.object,
  handleOpenConfig: PropTypes.func,
  startDate: PropTypes.string,
  endDate: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(AttackPatternsDistribution);
