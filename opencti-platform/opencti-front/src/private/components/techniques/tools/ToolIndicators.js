import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { Route, withRouter } from 'react-router-dom';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import inject18n from '../../../../components/i18n';
import ToolPopover from './ToolPopover';
import StixRelation from '../../common/stix_relations/StixRelation';
import EntityIndicators from '../../signatures/indicators/EntityIndicators';
import StixDomainEntityHeader from '../../common/stix_domain_entities/StixDomainEntityHeader';

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

class ToolIndicatorsComponent extends Component {
  constructor(props) {
    super(props);
    this.state = { withPadding: false };
  }

  render() {
    const { withPadding } = this.state;
    const { classes, tool, location } = this.props;
    const link = `/dashboard/techniques/tools/${tool.id}/indicators`;
    let className = classes.containerWithPadding;
    if (
      location.pathname.includes(
        `/dashboard/threats/tools/${tool.id}/indicators/relations/`,
      )
    ) {
      className = classes.containerWithoutPadding;
    } else if (withPadding) {
      className = classes.containerWithPaddingExport;
    }
    return (
      <div className={className}>
        <StixDomainEntityHeader
          stixDomainEntity={tool}
          PopoverComponent={<ToolPopover />}
        />
        <Route
          exact
          path="/dashboard/techniques/tools/:toolId/indicators/relations/:relationId"
          render={(routeProps) => (
            <StixRelation entityId={tool.id} {...routeProps} />
          )}
        />
        <Route
          exact
          path="/dashboard/techniques/tools/:toolId/indicators"
          render={(routeProps) => (
            <Paper classes={{ root: classes.paper }} elevation={2}>
              <EntityIndicators
                entityId={tool.id}
                relationType="indicates"
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

ToolIndicatorsComponent.propTypes = {
  tool: PropTypes.object,
  location: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const ToolIndicators = createFragmentContainer(ToolIndicatorsComponent, {
  tool: graphql`
    fragment ToolIndicators_tool on Tool {
      id
      name
      alias
    }
  `,
});

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(ToolIndicators);
