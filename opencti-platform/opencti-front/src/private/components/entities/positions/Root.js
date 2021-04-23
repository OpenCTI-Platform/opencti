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
import Position from './Position';
import PositionKnowledge from './PositionKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import PositionPopover from './PositionPopover';
import Loader from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import ErrorNotFound from '../../../../components/ErrorNotFound';

const subscription = graphql`
  subscription RootPositionsSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on Position {
        ...Position_position
        ...PositionEditionContainer_position
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
    }
  }
`;

const positionQuery = graphql`
  query RootPositionQuery($id: String!) {
    position(id: $id) {
      id
      name
      x_opencti_aliases
      ...Position_position
      ...PositionKnowledge_position
      ...FileImportViewer_entity
      ...FileExportViewer_entity
    }
    connectorsForExport {
      ...FileManager_connectorsExport
    }
  }
`;

class RootPosition extends Component {
  componentDidMount() {
    const {
      match: {
        params: { positionId },
      },
    } = this.props;
    const sub = requestSubscription({
      subscription,
      variables: { id: positionId },
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
        params: { positionId },
      },
    } = this.props;
    const link = `/dashboard/entities/positions/${positionId}/knowledge`;
    return (
      <div>
        <TopBar me={me || null} />
        <Route path="/dashboard/entities/positions/:positionId/knowledge">
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
          query={positionQuery}
          variables={{ id: positionId }}
          render={({ props }) => {
            if (props) {
              if (props.position) {
                return (
                  <Switch>
                    <Route
                      exact
                      path="/dashboard/entities/positions/:positionId"
                      render={(routeProps) => (
                        <Position {...routeProps} position={props.position} />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/entities/positions/:positionId/knowledge"
                      render={() => (
                        <Redirect
                          to={`/dashboard/entities/positions/${positionId}/knowledge/overview`}
                        />
                      )}
                    />
                    <Route
                      path="/dashboard/entities/positions/:positionId/knowledge"
                      render={(routeProps) => (
                        <PositionKnowledge
                          {...routeProps}
                          position={props.position}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/entities/positions/:positionId/analysis"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            stixDomainObject={props.position}
                            PopoverComponent={<PositionPopover />}
                          />
                          <StixCoreObjectOrStixCoreRelationshipContainers
                            {...routeProps}
                            stixCoreObjectOrStixCoreRelationshipId={positionId}
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/entities/positions/:positionId/files"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            stixDomainObject={props.position}
                            PopoverComponent={<PositionPopover />}
                          />
                          <FileManager
                            {...routeProps}
                            id={positionId}
                            connectorsImport={[]}
                            connectorsExport={props.connectorsForExport}
                            entity={props.position}
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/entities/positions/:positionId/history"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            stixDomainObject={props.position}
                            PopoverComponent={<PositionPopover />}
                          />
                          <StixCoreObjectHistory
                            {...routeProps}
                            stixCoreObjectId={positionId}
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

RootPosition.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootPosition);
