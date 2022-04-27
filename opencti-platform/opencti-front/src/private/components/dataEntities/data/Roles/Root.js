/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  Route, Redirect, withRouter, Switch,
} from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import { QueryRenderer as QR } from 'react-relay';
import QueryRendererDarkLight from '../../../../../relay/environmentDarkLight';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../../relay/environment';
import TopBar from '../../../nav/TopBar';
import EntityRole from './EntityRole';
import Loader from '../../../../../components/Loader';
import ErrorNotFound from '../../../../../components/ErrorNotFound';
import StixCoreObjectKnowledgeBar from '../../../common/stix_core_objects/StixCoreObjectKnowledgeBar';

const subscription = graphql`
  subscription RootRoleSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      # ... on ThreatActor {
        # ...Device_device
        # ...DeviceEditionContainer_device
      # }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
    }
  }
`;

const roleQuery = graphql`
  query RootRoleQuery($id: ID!) {
    oscalRole(id: $id) {
      id
      name
      ...EntityRole_role
    }
  }
`;

class RootRole extends Component {
  constructor(props) {
    super(props);
    const {
      match: {
        params: { roleId },
      },
    } = props;
    this.sub = requestSubscription({
      subscription,
      variables: { id: roleId },
    });
  }

  componentWillUnmount() {
    this.sub.dispose();
  }

  render() {
    const {
      me,
      match: {
        params: { roleId },
      },
    } = this.props;
    const link = `/data/entities/roles/${roleId}/knowledge`;
    return (
      <div>
        <TopBar me={me || null} />
        <Route path="/data/entities/roles/:roleId/knowledge">
          <StixCoreObjectKnowledgeBar
            stixCoreObjectLink={link}
            availableSections={[
              'victimology',
              'devices',
              'network',
              'software',
              'incidents',
              'malwares',
              'attack_patterns',
              'tools',
              'vulnerabilities',
              'observables',
              'infrastructures',
              'sightings',
            ]}
          />
        </Route>
        {/* <QueryRenderer */}
        <QR
          environment={QueryRendererDarkLight}
          query={roleQuery}
          variables={{ id: roleId }}
          render={({ error, props, retry }) => {
            if (props) {
              if (props.oscalRole) {
                return (
                  <Switch>
                    <Route
                      exact
                      path="/data/entities/roles/:roleId"
                      render={(routeProps) => (
                        <EntityRole
                          {...routeProps}
                          refreshQuery={retry}
                          role={props.oscalRole}
                        />
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

RootRole.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootRole);
