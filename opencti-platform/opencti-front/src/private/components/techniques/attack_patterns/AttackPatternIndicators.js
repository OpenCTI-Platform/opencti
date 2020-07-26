import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { Route, withRouter } from 'react-router-dom';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import inject18n from '../../../../components/i18n';
import AttackPatternPopover from './AttackPatternPopover';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import EntityIndicators from '../../signatures/indicators/EntityIndicators';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';

const styles = (theme) => ({
  container: {
    transition: theme.transitions.create('padding', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.leavingScreen,
    }),
  },
  containerWithPadding: {
    flexGrow: 1,
    transition: theme.transitions.create('padding', {
      easing: theme.transitions.easing.easeOut,
      duration: theme.transitions.duration.enteringScreen,
    }),
    paddingRight: 250,
  },
  containerWithPaddingExport: {
    flexGrow: 1,
    transition: theme.transitions.create('padding', {
      easing: theme.transitions.easing.easeOut,
      duration: theme.transitions.duration.enteringScreen,
    }),
    paddingRight: 560,
  },
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '5px 0 40px 0',
    padding: '25px 15px 15px 15px',
    borderRadius: 6,
  },
});

class AttackPatternIndicatorsComponent extends Component {
  constructor(props) {
    super(props);
    this.state = { withPadding: false };
  }

  render() {
    const { withPadding } = this.state;
    const { classes, attackPattern, location } = this.props;
    const link = `/dashboard/techniques/attack_patterns/${attackPattern.id}/indicators`;
    let className = classes.containerWithPadding;
    if (
      location.pathname.includes(
        `/dashboard/techniques/attack_patterns/${attackPattern.id}/indicators/relations/`,
      )
    ) {
      className = classes.containerWithoutPadding;
    } else if (withPadding) {
      className = classes.containerWithPaddingExport;
    }
    return (
      <div className={className}>
        <StixDomainObjectHeader
          stixDomainObject={attackPattern}
          PopoverComponent={<AttackPatternPopover />}
        />
        <Route
          exact
          path="/dashboard/techniques/attack_patterns/:attackPatternId/indicators/relations/:relationId"
          render={(routeProps) => (
            <StixCoreRelationship
              entityId={attackPattern.id}
              paddingRight={false}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/techniques/attack_patterns/:attackPatternId/indicators"
          render={(routeProps) => (
            <Paper classes={{ root: classes.paper }} elevation={2}>
              <EntityIndicators
                entityId={attackPattern.id}
                relationship_type="indicates"
                entityLink={link}
                {...routeProps}
              />
            </Paper>
          )}
        />
      </div>
    );
  }
}

AttackPatternIndicatorsComponent.propTypes = {
  attackPattern: PropTypes.object,
  location: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const AttackPatternIndicators = createFragmentContainer(
  AttackPatternIndicatorsComponent,
  {
    attackPattern: graphql`
      fragment AttackPatternIndicators_attackPattern on AttackPattern {
        id
        name
        aliases
      }
    `,
  },
);

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(AttackPatternIndicators);
