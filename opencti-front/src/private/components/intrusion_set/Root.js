import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Redirect, withRouter } from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import { QueryRenderer, requestSubscription } from '../../../relay/environment';
import TopBar from '../nav/TopBar';
import IntrusionSet from './IntrusionSet';
import IntrusionSetReports from './IntrusionSetReports';
import IntrusionSetKnowledge from './IntrusionSetKnowledge';
import IntrusionSetObservables from './IntrusionSetObservables';

const subscription = graphql`
  subscription RootIntrusionSetSubscription($id: ID!) {
    stixDomainEntity(id: $id) {
      ... on IntrusionSet {
        ...IntrusionSet_intrusionSet
        ...IntrusionSetEditionContainer_intrusionSet
      }
      ...StixDomainEntityKnowledgeGraph_stixDomainEntity
    }
  }
`;

const intrusionSetQuery = graphql`
  query RootIntrusionSetQuery($id: String!) {
    intrusionSet(id: $id) {
      ...IntrusionSet_intrusionSet
      ...IntrusionSetHeader_intrusionSet
      ...IntrusionSetOverview_intrusionSet
      ...IntrusionSetIdentity_intrusionSet
      ...IntrusionSetReports_intrusionSet
      ...IntrusionSetKnowledge_intrusionSet
      ...IntrusionSetObservables_intrusionSet
    }
  }
`;

class RootIntrusionSet extends Component {
  componentDidMount() {
    const {
      match: {
        params: { intrusionSetId },
      },
    } = this.props;
    const sub = requestSubscription({
      subscription,
      variables: { id: intrusionSetId },
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
        params: { intrusionSetId },
      },
    } = this.props;
    return (
      <div>
        <TopBar me={me || null} />
        <QueryRenderer
          query={intrusionSetQuery}
          variables={{ id: intrusionSetId }}
          render={({ props }) => {
            if (props && props.intrusionSet) {
              return (
                <div>
                  <Route
                    exact
                    path="/dashboard/knowledge/intrusion_sets/:intrusionSetId"
                    render={routeProps => (
                      <IntrusionSet
                        {...routeProps}
                        intrusionSet={props.intrusionSet}
                      />
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/knowledge/intrusion_sets/:intrusionSetId/reports"
                    render={routeProps => (
                      <IntrusionSetReports
                        {...routeProps}
                        intrusionSet={props.intrusionSet}
                      />
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/knowledge/intrusion_sets/:intrusionSetId/knowledge"
                    render={() => (
                      <Redirect
                        to={`/dashboard/knowledge/intrusion_sets/${intrusionSetId}/knowledge/overview`}
                      />
                    )}
                  />
                  <Route
                    path="/dashboard/knowledge/intrusion_sets/:intrusionSetId/knowledge"
                    render={routeProps => (
                      <IntrusionSetKnowledge
                        {...routeProps}
                        intrusionSet={props.intrusionSet}
                      />
                    )}
                  />
                  <Route
                    path="/dashboard/knowledge/intrusion_sets/:intrusionSetId/observables"
                    render={routeProps => (
                      <IntrusionSetObservables
                        {...routeProps}
                        intrusionSet={props.intrusionSet}
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

RootIntrusionSet.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootIntrusionSet);
