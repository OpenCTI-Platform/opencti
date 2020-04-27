import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Redirect, withRouter } from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../relay/environment';
import TopBar from '../../nav/TopBar';
import AttackPattern from './AttackPattern';
import AttackPatternReports from './AttackPatternReports';
import AttackPatternKnowledge from './AttackPatternKnowledge';
import StixDomainEntityHeader from '../../common/stix_domain_entities/StixDomainEntityHeader';
import FileManager from '../../common/files/FileManager';
import AttackPatternPopover from './AttackPatternPopover';
import Loader from '../../../../components/Loader';
import StixObjectHistory from '../../common/stix_object/StixObjectHistory';

const subscription = graphql`
  subscription RootAttackPatternSubscription($id: ID!) {
    stixDomainEntity(id: $id) {
      ... on AttackPattern {
        ...AttackPattern_attackPattern
        ...AttackPatternEditionContainer_attackPattern
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
    }
  }
`;

const attackPatternQuery = graphql`
  query RootAttackPatternQuery($id: String!) {
    attackPattern(id: $id) {
      id
      name
      alias
      ...AttackPattern_attackPattern
      ...AttackPatternReports_attackPattern
      ...AttackPatternKnowledge_attackPattern
      ...FileImportViewer_entity
      ...FileExportViewer_entity
    }
    connectorsForExport {
      ...FileManager_connectorsExport
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
                    render={(routeProps) => (
                      <AttackPattern
                        {...routeProps}
                        attackPattern={props.attackPattern}
                      />
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/techniques/attack_patterns/:attackPatternId/reports"
                    render={(routeProps) => (
                      <AttackPatternReports
                        {...routeProps}
                        attackPattern={props.attackPattern}
                      />
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/techniques/attack_patterns/:attackPatternId/knowledge"
                    render={() => (
                      <Redirect
                        to={`/dashboard/techniques/attack_patterns/${attackPatternId}/knowledge/overview`}
                      />
                    )}
                  />
                  <Route
                    path="/dashboard/techniques/attack_patterns/:attackPatternId/knowledge"
                    render={(routeProps) => (
                      <AttackPatternKnowledge
                        {...routeProps}
                        attackPattern={props.attackPattern}
                      />
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/techniques/attack_patterns/:attackPatternId/files"
                    render={(routeProps) => (
                      <React.Fragment>
                        <StixDomainEntityHeader
                          stixDomainEntity={props.attackPattern}
                          PopoverComponent={<AttackPatternPopover />}
                        />
                        <FileManager
                          {...routeProps}
                          id={attackPatternId}
                          connectorsExport={props.connectorsForExport}
                          entity={props.attackPattern}
                        />
                      </React.Fragment>
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/techniques/attack_patterns/:attackPatternId/history"
                    render={(routeProps) => (
                      <React.Fragment>
                        <StixDomainEntityHeader
                          stixDomainEntity={props.attackPattern}
                          PopoverComponent={<AttackPatternPopover />}
                        />
                        <StixObjectHistory
                          {...routeProps}
                          entityId={attackPatternId}
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

RootAttackPattern.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootAttackPattern);
