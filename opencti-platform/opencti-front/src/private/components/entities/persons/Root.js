import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Redirect, withRouter } from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../relay/environment';
import TopBar from '../../nav/TopBar';
import Person from './Person';
import PersonReports from './PersonReports';
import PersonKnowledge from './PersonKnowledge';

const subscription = graphql`
  subscription RootPersonsSubscription($id: ID!) {
    stixDomainEntity(id: $id) {
      ... on User {
        ...Person_person
        ...PersonEditionContainer_person
      }
    }
  }
`;

const personQuery = graphql`
  query RootPersonQuery($id: String!) {
    user(id: $id) {
      ...Person_person
      ...PersonHeader_person
      ...PersonOverview_person
      ...PersonReports_person
      ...PersonKnowledge_person
    }
  }
`;

class RootPerson extends Component {
  componentDidMount() {
    const {
      match: {
        params: { personId },
      },
    } = this.props;
    const sub = requestSubscription({
      subscription,
      variables: { id: personId },
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
        params: { personId },
      },
    } = this.props;
    return (
      <div>
        <TopBar me={me || null} />
        <QueryRenderer
          query={personQuery}
          variables={{ id: personId }}
          render={({ props }) => {
            if (props && props.user) {
              return (
                <div>
                  <Route
                    exact
                    path="/dashboard/entities/persons/:personId"
                    render={routeProps => (
                      <Person {...routeProps} person={props.user} />
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/entities/persons/:personId/reports"
                    render={routeProps => (
                      <PersonReports {...routeProps} person={props.user} />
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/entities/persons/:personId/knowledge"
                    render={() => (
                      <Redirect
                        to={`/dashboard/entities/persons/${personId}/knowledge/overview`}
                      />
                    )}
                  />
                  <Route
                    path="/dashboard/entities/persons/:personId/knowledge"
                    render={routeProps => (
                      <PersonKnowledge {...routeProps} person={props.user} />
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

RootPerson.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootPerson);
