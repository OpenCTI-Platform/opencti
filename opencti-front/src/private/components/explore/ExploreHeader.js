import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Typography from '@material-ui/core/Typography';
import inject18n from '../../../components/i18n';

const styles = () => ({
  title: {
    float: 'left',
    textTransform: 'uppercase',
  },
});

class ExploreHeaderComponent extends Component {
  render() {
    const { t, classes, stixDomainEntity } = this.props;
    return (
      <div style={{ marginBottom: 15 }}>
        <Typography variant='h1' gutterBottom={true} classes={{ root: classes.title }}>
          {stixDomainEntity.name}
        </Typography>
        <div className='clearfix'/>
      </div>
    );
  }
}

ExploreHeaderComponent.propTypes = {
  stixDomainEntity: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const ExploreHeader = createFragmentContainer(ExploreHeaderComponent, {
  stixDomainEntity: graphql`
      fragment ExploreHeader_stixDomainEntity on StixDomainEntity {
          id,
          name
      }
  `,
});

export default compose(
  inject18n,
  withStyles(styles),
)(ExploreHeader);
