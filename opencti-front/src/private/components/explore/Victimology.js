import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import inject18n from '../../../components/i18n';
import VictiomologyRightBar from './VictimologyRightBar';
import EntityStixRelationsChart from '../stix_relation/EntityStixRelationsChart';

const styles = () => ({
  container: {
    margin: 0,
  },
  content: {
    paddingRight: 260,
  },
});

class Victimology extends Component {
  render() {
    const { classes } = this.props;
    return (
      <div className={classes.container}>
        <VictiomologyRightBar />
        <div className={classes.content}>
          <EntityStixRelationsChart relationType='targets' toTypes={['Identity']} title='Targeted entities through time'/>
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
