/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  Route, Redirect, withRouter, Switch,
} from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../../relay/environment';
import EntityRole from './EntityAssessmentPlatform';
import Loader from '../../../../../components/Loader';
import ErrorNotFound from '../../../../../components/ErrorNotFound';
import StixCoreObjectKnowledgeBar from '../../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import { toastGenericError } from "../../../../../utils/bakedToast";

const subscription = graphql`
  subscription RootAssessentPlatformSubscription($id: ID!) {
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

const assessmentPlatformQuery = graphql`
  query RootAssessmentPlatformQuery($id: ID!) {
    assessmentPlatform(id: $id) {
      id
      name
      ...EntityAssessmentPlatform_assessmentPlatform
    }
  }
`;

class RootAssessmentPlatform extends Component {
  constructor(props) {
    super(props);
    const {
      match: {
        params: { assessmentPlatformId },
      },
    } = props;
    this.sub = requestSubscription({
      subscription,
      variables: { id: assessmentPlatformId },
    });
  }

  componentWillUnmount() {
    this.sub.dispose();
  }

  render() {
    const {
      me,
      match: {
        params: { assessmentPlatformId },
      },
    } = this.props;
    const link = `/data/entities/assessment_platform/${assessmentPlatformId}/knowledge`;
    return (
      <div>
        <Route path="/data/entities/assessment_platform/:assessmentPlatformId/knowledge">
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
          query={assessmentPlatformQuery}
          variables={{ id: assessmentPlatformId }}
          render={({ error, props, retry }) => {
            if (error) {
              console.error(error);
              toastGenericError('Failed to get assessment platform data');
            }
            if (props) {
              if (props.assessmentPlatform) {
                return (
                  <Switch>
                    <Route
                      exact
                      path="/data/entities/assessment_platform/:assessmentPlatformId"
                      render={(routeProps) => (
                        <EntityRole
                          {...routeProps}
                          refreshQuery={retry}
                          assessmentPlatform={props.assessmentPlatform}
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

RootAssessmentPlatform.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootAssessmentPlatform);
