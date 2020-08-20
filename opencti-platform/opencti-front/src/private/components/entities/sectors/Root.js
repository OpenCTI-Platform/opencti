import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Redirect, withRouter } from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../relay/environment';
import TopBar from '../../nav/TopBar';
import Sector from './Sector';
import SectorReports from './SectorReports';
import SectorKnowledge from './SectorKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import SectorPopover from './SectorPopover';
import FileManager from '../../common/files/FileManager';
import Loader from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';

const subscription = graphql`
  subscription RootSectorSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on Sector {
        ...Sector_sector
        ...SectorEditionContainer_sector
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
    }
  }
`;

const sectorQuery = graphql`
  query RootSectorQuery($id: String!) {
    sector(id: $id) {
      ...Sector_sector
      ...SectorReports_sector
      ...SectorKnowledge_sector
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      id
      name
      x_opencti_aliases
    }
    connectorsForExport {
      ...FileManager_connectorsExport
    }
  }
`;

class RootSector extends Component {
  componentDidMount() {
    const {
      match: {
        params: { sectorId },
      },
    } = this.props;
    const sub = requestSubscription({
      subscription,
      variables: { id: sectorId },
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
        params: { sectorId },
      },
    } = this.props;
    return (
      <div>
        <TopBar me={me || null} />
        <QueryRenderer
          query={sectorQuery}
          variables={{ id: sectorId }}
          render={({ props }) => {
            if (props && props.sector) {
              return (
                <div>
                  <Route
                    exact
                    path="/dashboard/entities/sectors/:sectorId"
                    render={(routeProps) => (
                      <Sector {...routeProps} sector={props.sector} />
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/entities/sectors/:sectorId/reports"
                    render={(routeProps) => (
                      <SectorReports {...routeProps} sector={props.sector} />
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/entities/sectors/:sectorId/knowledge"
                    render={() => (
                      <Redirect
                        to={`/dashboard/entities/sectors/${sectorId}/knowledge/overview`}
                      />
                    )}
                  />
                  <Route
                    path="/dashboard/entities/sectors/:sectorId/knowledge"
                    render={(routeProps) => (
                      <SectorKnowledge {...routeProps} sector={props.sector} />
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/entities/sectors/:sectorId/files"
                    render={(routeProps) => (
                      <React.Fragment>
                        <StixDomainObjectHeader
                          stixDomainObject={props.sector}
                          PopoverComponent={<SectorPopover />}
                        />
                        <FileManager
                          {...routeProps}
                          id={sectorId}
                          connectorsExport={props.connectorsForExport}
                          entity={props.sector}
                        />
                      </React.Fragment>
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/entities/sectors/:sectorId/history"
                    render={(routeProps) => (
                      <React.Fragment>
                        <StixDomainObjectHeader
                          stixDomainObject={props.sector}
                          PopoverComponent={<SectorPopover />}
                        />
                        <StixCoreObjectHistory
                          {...routeProps}
                          entityId={sectorId}
                        />
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

RootSector.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootSector);
