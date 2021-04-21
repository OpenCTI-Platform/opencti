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
import Region from './Region';
import RegionKnowledge from './RegionKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import RegionPopover from './RegionPopover';
import Loader from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import ErrorNotFound from '../../../../components/ErrorNotFound';

const subscription = graphql`
  subscription RootRegionsSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on Region {
        ...Region_region
        ...RegionEditionContainer_region
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
    }
  }
`;

const regionQuery = graphql`
  query RootRegionQuery($id: String!) {
    region(id: $id) {
      id
      name
      x_opencti_aliases
      ...Region_region
      ...RegionKnowledge_region
      ...FileImportViewer_entity
      ...FileExportViewer_entity
    }
    connectorsForExport {
      ...FileManager_connectorsExport
    }
  }
`;

class RootRegion extends Component {
  componentDidMount() {
    const {
      match: {
        params: { regionId },
      },
    } = this.props;
    const sub = requestSubscription({
      subscription,
      variables: { id: regionId },
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
        params: { regionId },
      },
    } = this.props;
    const link = `/dashboard/entities/regions/${regionId}/knowledge`;
    return (
      <div>
        <TopBar me={me || null} />
        <Route path="/dashboard/entities/regions/:regionId/knowledge">
          <StixCoreObjectKnowledgeBar
            stixCoreObjectLink={link}
            availableSections={[
              'countries',
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
          query={regionQuery}
          variables={{ id: regionId }}
          render={({ props }) => {
            if (props) {
              if (props.region) {
                return (
                  <Switch>
                    <Route
                      exact
                      path="/dashboard/entities/regions/:regionId"
                      render={(routeProps) => (
                        <Region {...routeProps} region={props.region} />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/entities/regions/:regionId/knowledge"
                      render={() => (
                        <Redirect
                          to={`/dashboard/entities/regions/${regionId}/knowledge/overview`}
                        />
                      )}
                    />
                    <Route
                      path="/dashboard/entities/regions/:regionId/knowledge"
                      render={(routeProps) => (
                        <RegionKnowledge
                          {...routeProps}
                          region={props.region}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/entities/regions/:regionId/analysis"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            stixDomainObject={props.region}
                            PopoverComponent={<RegionPopover />}
                          />
                          <StixCoreObjectOrStixCoreRelationshipContainers
                            {...routeProps}
                            stixCoreObjectOrStixCoreRelationshipId={regionId}
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/entities/regions/:regionId/files"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            stixDomainObject={props.region}
                            PopoverComponent={<RegionPopover />}
                          />
                          <FileManager
                            {...routeProps}
                            id={regionId}
                            connectorsImport={[]}
                            connectorsExport={props.connectorsForExport}
                            entity={props.region}
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/entities/regions/:regionId/history"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            stixDomainObject={props.region}
                            PopoverComponent={<RegionPopover />}
                          />
                          <StixCoreObjectHistory
                            {...routeProps}
                            stixCoreObjectId={regionId}
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

RootRegion.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootRegion);
