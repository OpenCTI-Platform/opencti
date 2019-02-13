import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose, filter, append } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import inject18n from '../../../components/i18n';
import VictiomologyRightBar from './VictimologyRightBar';
import EntityStixRelationsChart from '../stix_relation/EntityStixRelationsChart';
import EntityStixRelationsPie from '../stix_relation/EntityStixRelationsPie';

const styles = () => ({
  container: {
    margin: 0,
  },
  content: {
    paddingRight: 260,
  },
});

class Victimology extends Component {
  constructor(props) {
    super(props);
    this.state = { selectedThreat: null, selectedTargetingTypes: null, selectedTargetTypes: null };
  }

  handleSelectThreat(name, value) {
    this.setState({ selectedThreat: value.value });
  }

  handleSelectTargetingType(targetingType) {
    if (targetingType === 'All') {
      this.setState({ selectedTargetingTypes: null });
    } else if (this.state.selectedTargetingTypes !== null && this.state.selectedTargetingTypes.indexOf(targetingType) !== -1) {
      this.setState({
        selectedTargetingTypes: filter(t => t !== targetingType, this.state.selectedTargetingTypes),
      });
    } else {
      this.setState({
        selectedTargetingTypes: append(targetingType, this.state.selectedTargetingTypes),
      });
    }
  }

  handleSelectTargetType(targetType) {
    if (targetType === 'All') {
      this.setState({ selectedTargetTypes: null });
    } else if (this.state.selectedTargetTypes !== null && this.state.selectedTargetTypes.indexOf(targetType) !== -1) {
      this.setState({
        selectedTargetTypes: filter(t => t !== targetType, this.state.selectedTargetTypes),
      });
    } else {
      this.setState({
        selectedTargetTypes: append(targetType, this.state.selectedTargetTypes),
      });
    }
  }

  render() {
    const { classes } = this.props;
    const resolveInference = this.state.selectedThreat !== null
      || this.state.selectedTargetingTypes !== null
      || this.state.selectedTargetTypes !== null;
    return (
      <div className={classes.container}>
        <VictiomologyRightBar
          handleSelectThreat={this.handleSelectThreat.bind(this)}
          handleSelectTargetingType={this.handleSelectTargetingType.bind(this)}
          selectedTargetingTypes={this.state.selectedTargetingTypes}
          handleSelectTargetType={this.handleSelectTargetType.bind(this)}
          selectedTargetTypes={this.state.selectedTargetTypes}
        />
        <div className={classes.content}>
          <EntityStixRelationsChart
            entityId={this.state.selectedThreat}
            entityTypes={this.state.selectedTargetingTypes}
            relationType='targets'
            toTypes={['Identity']}
            title='Targeted entities through time'
            resolveInferences={resolveInference}
            resolveRelationType='attributed-to'
          />
          <Grid container={true} spacing={16} style={{ marginTop: 20 }}>
            <Grid item={true} xs={6}>
              <EntityStixRelationsPie
                entityId={this.state.selectedThreat}
                entityType='Sector'
                entityTypes={this.state.selectedTargetingTypes}
                relationType='targets'
                field='name'
                resolveInferences={resolveInference}
                resolveRelationType='attributed-to'
              />
            </Grid>
            <Grid item={true} xs={6}>
              <EntityStixRelationsPie
                entityId={this.state.selectedThreat}
                entityType='Country'
                entityTypes={this.state.selectedTargetingTypes}
                relationType='targets'
                field='name'
                resolveInferences={resolveInference}
                resolveRelationType='attributed-to'
              />
            </Grid>
          </Grid>
        </div>
      </div>
    );
  }
}

Victimology.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(Victimology);
