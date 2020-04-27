import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Redirect, withRouter } from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../relay/environment';
import TopBar from '../../nav/TopBar';
import City from './City';
import CityReports from './CityReports';
import CityKnowledge from './CityKnowledge';
import CityObservables from './CityObservables';
import StixDomainEntityHeader from '../../common/stix_domain_entities/StixDomainEntityHeader';
import FileManager from '../../common/files/FileManager';
import CityPopover from './CityPopover';
import Loader from '../../../../components/Loader';
import StixObjectHistory from '../../common/stix_object/StixObjectHistory';

const subscription = graphql`
  subscription RootCitiesSubscription($id: ID!) {
    stixDomainEntity(id: $id) {
      ... on City {
        ...City_city
        ...CityEditionContainer_city
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
    }
  }
`;

const cityQuery = graphql`
  query RootCityQuery($id: String!) {
    city(id: $id) {
      id
      name
      alias
      ...City_city
      ...CityReports_city
      ...CityKnowledge_city
      ...CityObservables_city
      ...FileImportViewer_entity
      ...FileExportViewer_entity
    }
    connectorsForExport {
      ...FileManager_connectorsExport
    }
  }
`;

class RootCity extends Component {
  componentDidMount() {
    const {
      match: {
        params: { cityId },
      },
    } = this.props;
    const sub = requestSubscription({
      subscription,
      variables: { id: cityId },
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
        params: { cityId },
      },
    } = this.props;
    return (
      <div>
        <TopBar me={me || null} />
        <QueryRenderer
          query={cityQuery}
          variables={{ id: cityId }}
          render={({ props }) => {
            if (props && props.city) {
              return (
                <div>
                  <Route
                    exact
                    path="/dashboard/entities/cities/:cityId"
                    render={(routeProps) => (
                      <City {...routeProps} city={props.city} />
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/entities/cities/:cityId/reports"
                    render={(routeProps) => (
                      <CityReports {...routeProps} city={props.city} />
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/entities/cities/:cityId/knowledge"
                    render={() => (
                      <Redirect
                        to={`/dashboard/entities/cities/${cityId}/knowledge/overview`}
                      />
                    )}
                  />
                  <Route
                    path="/dashboard/entities/cities/:cityId/knowledge"
                    render={(routeProps) => (
                      <CityKnowledge {...routeProps} city={props.city} />
                    )}
                  />
                  <Route
                    path="/dashboard/entities/cities/:cityId/observables"
                    render={(routeProps) => (
                      <CityObservables {...routeProps} city={props.city} />
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/entities/cities/:cityId/files"
                    render={(routeProps) => (
                      <React.Fragment>
                        <StixDomainEntityHeader
                          stixDomainEntity={props.city}
                          PopoverComponent={<CityPopover />}
                        />
                        <FileManager
                          {...routeProps}
                          id={cityId}
                          connectorsExport={props.connectorsForExport}
                          entity={props.city}
                        />
                      </React.Fragment>
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/entities/cities/:cityId/history"
                    render={(routeProps) => (
                      <React.Fragment>
                        <StixDomainEntityHeader
                          stixDomainEntity={props.city}
                          PopoverComponent={<CityPopover />}
                        />
                        <StixObjectHistory {...routeProps} entityId={cityId} />
                      </React.Fragment>
                    )}
                  />
                </div>
              );
            }
            return <Loader />;
          }}
        />
      </div>
    );
  }
}

RootCity.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootCity);
