import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose, propOr, pathOr } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import inject18n from '../../../components/i18n';
import EntityStixRelationsChart from '../common/stix_relations/EntityStixRelationsChart';
import EntityStixRelationsTableTime from '../common/stix_relations/EntityStixRelationsTableTime';

const styles = () => ({
  container: {
    margin: 0,
  },
});

class VictimologyDistribution extends Component {
  render() {
    const {
      configuration,
      handleOpenConfig,
      inferred,
      startDate,
      endDate,
    } = this.props;
    switch (configuration.graph_type) {
      case 'table':
        return (
          <EntityStixRelationsTableTime
            variant="explore"
            configuration={configuration}
            handleOpenConfig={handleOpenConfig.bind(this)}
            title={propOr('Widget', 'title', configuration)}
            entityId={pathOr(null, ['entity', 'id'], configuration)}
            relationType="targets"
            field="name"
            inferred={inferred}
            startDate={startDate}
            endDate={endDate}
          />
        );
      case 'line':
        return (
          <EntityStixRelationsChart
            variant="explore"
            configuration={configuration}
            handleOpenConfig={handleOpenConfig.bind(this)}
            title={propOr('Widget', 'title', configuration)}
            entityId={pathOr(null, ['entity', 'id'], configuration)}
            relationType="targets"
            inferred={inferred}
            startDate={startDate}
            endDate={endDate}
          />
        );
      default:
        return (
          <EntityStixRelationsChart
            variant="explore"
            configuration={configuration}
            handleOpenConfig={handleOpenConfig.bind(this)}
            title={propOr('Widget', 'title', configuration)}
            entityId={pathOr(null, ['entity', 'id'], configuration)}
            relationType="targets"
            inferred={inferred}
            startDate={startDate}
            endDate={endDate}
          />
        );
    }
  }
}

VictimologyDistribution.propTypes = {
  configuration: PropTypes.object,
  handleOpenConfig: PropTypes.func,
  inferred: PropTypes.bool,
  startDate: PropTypes.string,
  endDate: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(inject18n, withStyles(styles))(VictimologyDistribution);
