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
import StixDomainEntityHeader from '../../common/stix_domain_entities/StixDomainEntityHeader';
import FileManager from '../../common/files/FileManager';
import PersonPopover from './PersonPopover';
import Loader from '../../../../components/Loader';

const subscription = graphql`
  subscription RootPersonsSubscription($id: ID!) {
    stixDomainEntity(id: $id) {
      ... on User {
        ...Person_person
        ...PersonEditionContainer_person
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
    }
  }
`;

const personQuery = graphql`
  query RootPersonQuery($id: String!) {
    user(id: $id) {
      id
      name
      alias
      ...Person_person
      ...PersonOverview_person
      ...PersonDetails_person
      ...PersonReports_person
      ...PersonKnowledge_person
      ...FileImportViewer_entity
      ...FileExportViewer_entity
    }
    connectorsForExport {
      ...FileManager_connectorsExport
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
                    render={(routeProps) => (
                      <Person {...routeProps} person={props.user} />
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/entities/persons/:personId/reports"
                    render={(routeProps) => (
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
                    render={(routeProps) => (
                      <PersonKnowledge {...routeProps} person={props.user} />
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/entities/persons/:personId/files"
                    render={(routeProps) => (
                      <React.Fragment>
                        <StixDomainEntityHeader
                          stixDomainEntity={props.user}
                          PopoverComponent={<PersonPopover />}
                        />
                        <FileManager
                          {...routeProps}
                          id={personId}
                          connectorsExport={props.connectorsForExport}
                          entity={props.user}
                        />
                      </React.Fragment>
                    )}
                  />
                </div>
              );
            }
            return <Loader variant="inElement" />;
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
