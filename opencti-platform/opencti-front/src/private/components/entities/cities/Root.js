import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  Route, Redirect, withRouter, Switch,
} from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../relay/environment';
import TopBar from '../../nav/TopBar';
import City from './City';
import CityKnowledge from './CityKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import CityPopover from './CityPopover';
import Loader from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import ErrorNotFound from '../../../../components/ErrorNotFound';

const subscription = graphql`
  subscription RootCitiesSubscription($id: ID!) {
    stixDomainObject(id: $id) {
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
      x_opencti_aliases
      ...City_city
      ...CityKnowledge_city
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
    const link = `/dashboard/entities/cities/${cityId}/knowledge`;
    return (
      <div>
        <TopBar me={me || null} />
        <Route path="/dashboard/entities/cities/:cityId/knowledge">
          <StixCoreObjectKnowledgeBar
            stixCoreObjectLink={link}
            availableSections={[
              'organizations',
              'threat_actors',
              'intrusion_sets',
              'campaigns',
              'incidents',
              'malwares',
              'observables',
              'sightings',
            ]}
          />
        </Route>
        <QueryRenderer
          query={cityQuery}
          variables={{ id: cityId }}
          render={({ props }) => {
            if (props) {
              if (props.city) {
                return (
                  <Switch>
                    <Route
                      exact
                      path="/dashboard/entities/cities/:cityId"
                      render={(routeProps) => (
                        <City {...routeProps} city={props.city} />
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
                      exact
                      path="/dashboard/entities/cities/:cityId/analysis"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            stixDomainObject={props.city}
                            PopoverComponent={<CityPopover />}
                          />
                          <StixCoreObjectOrStixCoreRelationshipContainers
                            {...routeProps}
                            stixCoreObjectOrStixCoreRelationshipId={cityId}
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/entities/cities/:cityId/files"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            stixDomainObject={props.city}
                            PopoverComponent={<CityPopover />}
                          />
                          <FileManager
                            {...routeProps}
                            id={cityId}
                            connectorsImport={[]}
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
                          <StixDomainObjectHeader
                            stixDomainObject={props.city}
                            PopoverComponent={<CityPopover />}
                          />
                          <StixCoreObjectHistory
                            {...routeProps}
                            stixCoreObjectId={cityId}
                          />
                        </React.Fragment>
                      )}
                    />
                  </Switch>
                );
              }
              return <ErrorNotFound />;
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
