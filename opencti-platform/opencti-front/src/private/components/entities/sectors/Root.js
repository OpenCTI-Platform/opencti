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

const subscription = graphql`
  subscription RootSectorSubscription($id: ID!) {
    stixDomainEntity(id: $id) {
      ... on Sector {
        ...Sector_sector
        ...SectorEditionContainer_sector
      }
    }
  }
`;

const sectorQuery = graphql`
  query RootSectorQuery($id: String!) {
    sector(id: $id) {
      ...Sector_sector
      ...SectorHeader_sector
      ...SectorOverview_sector
      ...SectorSubsectors_sector
      ...SectorReports_sector
      ...SectorKnowledge_sector
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
                    render={routeProps => (
                      <Sector {...routeProps} sector={props.sector} />
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/entities/sectors/:sectorId/reports"
                    render={routeProps => (
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
                    render={routeProps => (
                      <SectorKnowledge {...routeProps} sector={props.sector} />
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

RootSector.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootSector);
