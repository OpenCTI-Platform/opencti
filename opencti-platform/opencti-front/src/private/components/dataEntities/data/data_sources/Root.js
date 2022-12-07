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
import TopBar from '../../../nav/TopBar';
import DataSource from './DataSource';
import Loader from '../../../../../components/Loader';
import ErrorNotFound from '../../../../../components/ErrorNotFound';
import StixCoreObjectKnowledgeBar from '../../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import { toastGenericError } from "../../../../../utils/bakedToast";

const subscription = graphql`
  subscription RootDataSourceSubscription($id: ID!) {
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

const dataSourceQuery = graphql`
  query RootDataSourceQuery($id: ID!) {
    dataSource(id: $id) {
      id
      name
      ...DataSource_data
    }
  }
`;

class RootDataSource extends Component {
  constructor(props) {
    super(props);
    const {
      match: {
        params: { dataSourceId },
      },
    } = props;
    this.sub = requestSubscription({
      subscription,
      variables: { id: dataSourceId },
    });
  }

  componentWillUnmount() {
    this.sub.dispose();
  }

  render() {
    const {
      me,
      match: {
        params: { dataSourceId },
      },
    } = this.props;
    const link = `/data/data source/${dataSourceId}/knowledge`;
    return (
      <div>
        <TopBar me={me || null} />
        <Route path="/data/data source/:dataSourceId/knowledge">
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
          query={dataSourceQuery}
          variables={{ id: dataSourceId }}
          render={({ error, props, retry }) => {
            if (error) {
              console.error(error);
              toastGenericError('Failed to get location data');
            }
            if (props) {
              if (props.dataSource) {
                return (
                  <Switch>
                    <Route
                      exact
                      path="/data/data source/:dataSourceId"
                      render={(routeProps) => (
                        <DataSource
                          {...routeProps}
                          refreshQuery={retry}
                          location={props.dataSource}
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

RootDataSource.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootDataSource);
