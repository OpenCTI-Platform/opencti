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
import InformationSystem from './InformationSystem';
import Loader from '../../../../components/Loader';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';

const informationSystemQuery = graphql`
  query RootInformationSystemQuery($id: ID!) {
    softwareAsset(id: $id) {
      id
      name
      ...InformationSystem_information
    }
  }
`;

class RootInformationSystem extends Component {
  render() {
    const {
      me,
      match: {
        params: { informationSystemId },
      },
    } = this.props;
    const link = `/defender HQ/assets/information_systems/${informationSystemId}/knowledge`;
    return (
      <div>
        <Route path="/defender HQ/assets/information_systems/:informationSystemId/knowledge">
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
          query={informationSystemQuery}
          variables={{ id: informationSystemId }}
          render={({ props, retry }) => {
            if (props) {
              if (props.softwareAsset) {
                return (
                  <Switch>
                    <Route
                      exact
                      path="/defender HQ/assets/information_systems/:informationSystemId"
                      render={(routeProps) => (
                        <InformationSystem
                          {...routeProps}
                          refreshQuery={retry}
                          informationSystem={props.softwareAsset}
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

RootInformationSystem.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootInformationSystem);
