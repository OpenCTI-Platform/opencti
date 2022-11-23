import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  Route, withRouter, Switch,
} from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../../relay/environment';
import Remediation from './Remediation';
import Loader from '../../../../../components/Loader';
import ErrorNotFound from '../../../../../components/ErrorNotFound';
import StixCoreObjectKnowledgeBar from '../../../common/stix_core_objects/StixCoreObjectKnowledgeBar';

const subscription = graphql`
  subscription RootRemediationSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      # ... on ThreatActor {
      #   ...Device_device
      #   ...DeviceEditionContainer_device
      # }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
    }
  }
`;

const remediationQuery = graphql`
  query RootRemediationQuery($id: ID!) {
    riskResponse(id: $id) {
      id
      name
      ...Remediation_remediation
    }
  }
`;

class RootRemediation extends Component {
  constructor(props) {
    super(props);
    const {
      match: {
        params: { riskId },
      },
    } = props;
    this.sub = requestSubscription({
      subscription,
      variables: { id: riskId },
    });
  }

  componentWillUnmount() {
    this.sub.dispose();
  }

  render() {
    const {
      me,
      match: {
        params: { riskId, remediationId },
      },
      risk,
    } = this.props;
    const link = `/activities/risk assessment/risks/${riskId}/knowledge`;
    return (
      <div>
        <Route path="/activities/risk assessment/risks/:riskId/knowledge">
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
        <QueryRenderer
          query={remediationQuery}
          variables={{ id: remediationId }}
          render={({ props, retry }) => {
            if (props) {
              if (props.riskResponse) {
                return (
                  <Switch>
                    <Route
                      exact
                      path="/activities/risk assessment/risks/:riskId/remediation/:remediationId"
                      render={(routeProps) => (
                        <Remediation
                          {...routeProps}
                          riskId={riskId}
                          refreshQuery={retry}
                          risk={risk}
                          remediation={props.riskResponse}
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

RootRemediation.propTypes = {
  risk: PropTypes.object,
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootRemediation);
