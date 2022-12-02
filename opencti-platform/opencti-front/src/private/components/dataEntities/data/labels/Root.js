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
import EntityRole from './EntityLabel';
import Loader from '../../../../../components/Loader';
import ErrorNotFound from '../../../../../components/ErrorNotFound';
import StixCoreObjectKnowledgeBar from '../../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import { toastGenericError } from "../../../../../utils/bakedToast";

const subscription = graphql`
  subscription RootLabelsSubscription($id: ID!) {
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

const labelQuery = graphql`
  query RootLabelQuery($id: ID!) {
    cyioLabel(id: $id) {
      id
      name
      ...EntityLabel_label
    }
  }
`;

class RootLabel extends Component {
  constructor(props) {
    super(props);
    const {
      match: {
        params: { labelId },
      },
    } = props;
    this.sub = requestSubscription({
      subscription,
      variables: { id: labelId },
    });
  }

  componentWillUnmount() {
    this.sub.dispose();
  }

  render() {
    const {
      me,
      match: {
        params: { labelId },
      },
    } = this.props;
    const link = `/data/entities/labels/${labelId}/knowledge`;
    return (
      <div>
        <Route path="/data/entities/labels/:labelId/knowledge">
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
          query={labelQuery}
          variables={{ id: labelId }}
          render={({ error, props, retry }) => {
            if (error) {
              console.error(error);
              toastGenericError('Failed to get label data');
            }
            if (props) {
              if (props.cyioLabel) {
                return (
                  <Switch>
                    <Route
                      exact
                      path="/data/entities/labels/:labelId"
                      render={(routeProps) => (
                        <EntityRole
                          {...routeProps}
                          refreshQuery={retry}
                          label={props.cyioLabel}
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

RootLabel.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootLabel);
