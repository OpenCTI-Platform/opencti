import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Redirect, withRouter } from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import { QueryRenderer, requestSubscription } from '../../../relay/environment';
import TopBar from '../nav/TopBar';
import AttackPattern from './AttackPattern';
import AttackPatternReports from './AttackPatternReports';
import AttackPatternKnowledge from './AttackPatternKnowledge';

const subscription = graphql`
  subscription RootAttackPatternSubscription($id: ID!) {
    stixDomainEntity(id: $id) {
      ... on AttackPattern {
        ...AttackPattern_attackPattern
        ...AttackPatternEditionContainer_attackPattern
      }
    }
  }
`;

const attackPatternQuery = graphql`
  query RootAttackPatternQuery($id: String!) {
    attackPattern(id: $id) {
      ...AttackPattern_attackPattern
      ...AttackPatternHeader_attackPattern
      ...AttackPatternOverview_attackPattern
      ...AttackPatternIdentity_attackPattern
      ...AttackPatternReports_attackPattern
      ...AttackPatternKnowledge_attackPattern
    }
  }
`;

class RootAttackPattern extends Component {
  componentDidMount() {
    const {
      match: {
        params: { attackPatternId },
      },
    } = this.props;
    const sub = requestSubscription({
      subscription,
      variables: { id: attackPatternId },
    });
    this.setState({ sub });
  }

  componentWillUnmount() {
    this.state.sub.dispose();
  }

  render() {
    const {
      me,
      match: {
        params: { attackPatternId },
      },
    } = this.props;
    return (
      <div>
        <TopBar me={me || null} />
        <QueryRenderer
          query={attackPatternQuery}
          variables={{ id: attackPatternId }}
          render={({ props }) => {
            if (props && props.attackPattern) {
              return (
                <div>
                  <Route
                    exact
                    path="/dashboard/techniques/attack_patterns/:attackPatternId"
                    render={routeProps => (
                      <AttackPattern
                        {...routeProps}
                        attackPattern={props.attackPattern}
                      />
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/techniques/attack_patterns/:attackPatternId/reports"
                    render={routeProps => (
                      <AttackPatternReports
                        {...routeProps}
                        attackPattern={props.attackPattern}
                      />
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/techniques/attack_patterns/:attackPatternId/threats"
                    render={() => (
                      <Redirect
                        to={`/dashboard/techniques/attack_patterns/${attackPatternId}/threats/overview`}
                      />
                    )}
                  />
                  <Route
                    path="/dashboard/techniques/attack_patterns/:attackPatternId/threats"
                    render={routeProps => (
                      <AttackPatternKnowledge
                        {...routeProps}
                        attackPattern={props.attackPattern}
                      />
                    )}
                  />
                </div>
              );
            }
            return <div> &nbsp; </div>;
          }}
        />
      </div>
    );
  }
}

RootAttackPattern.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootAttackPattern);
