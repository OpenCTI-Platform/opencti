/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, withRouter, Switch } from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../relay/environment';
import Software from './Software';
import Loader from '../../../../components/Loader';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';

const subscription = graphql`
  subscription RootSoftwareSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      # ... on Campaign {
      #   # ...Software_software
      #   ...SoftwareEditionContainer_software
      # }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
    }
  }
`;

const softwareQuery = graphql`
  query RootSoftwareQuery($id: ID!) {
    softwareAsset(id: $id) {
      id
      name
      ...Software_software
    }
  }
`;

class RootSoftware extends Component {
  constructor(props) {
    super(props);
    const {
      match: {
        params: { softwareId },
      },
    } = props;
    this.sub = requestSubscription({
      subscription,
      variables: { id: softwareId },
    });
  }

  componentWillUnmount() {
    this.sub.dispose();
  }

  render() {
    const {
      me,
      match: {
        params: { softwareId },
      },
    } = this.props;
    const link = `/defender HQ/assets/software/${softwareId}/knowledge`;
    return (
      <div>
        <Route path="/defender HQ/assets/software/:softwareId/knowledge">
          <StixCoreObjectKnowledgeBar
            stixCoreObjectLink={link}
            availableSections={[
              'attribution',
              'victimology',
              'incidents',
              'malwares',
              'tools',
              'attack_patterns',
              'vulnerabilities',
              'observables',
              'infrastructures',
              'sightings',
            ]}
          />
        </Route>
        <QueryRenderer
          query={softwareQuery}
          variables={{ id: softwareId }}
          render={({ props, retry }) => {
            if (props) {
              if (props.softwareAsset) {
                return (
                  <Switch>
                    <Route
                      exact
                      path="/defender HQ/assets/software/:softwareId"
                      render={(routeProps) => (
                        <Software {...routeProps} refreshQuery={retry} software={props.softwareAsset} />
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

RootSoftware.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootSoftware);
