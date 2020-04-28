import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Redirect, withRouter } from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../relay/environment';
import TopBar from '../../nav/TopBar';
import IntrusionSet from './IntrusionSet';
import IntrusionSetReports from './IntrusionSetReports';
import IntrusionSetKnowledge from './IntrusionSetKnowledge';
import IntrusionSetIndicators from './IntrusionSetIndicators';
import StixDomainEntityHeader from '../../common/stix_domain_entities/StixDomainEntityHeader';
import FileManager from '../../common/files/FileManager';
import IntrusionSetPopover from './IntrusionSetPopover';
import Loader from '../../../../components/Loader';
import StixObjectHistory from '../../common/stix_object/StixObjectHistory';

const subscription = graphql`
  subscription RootIntrusionSetSubscription($id: ID!) {
    stixDomainEntity(id: $id) {
      ... on IntrusionSet {
        ...IntrusionSet_intrusionSet
        ...IntrusionSetEditionContainer_intrusionSet
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
    }
  }
`;

const intrusionSetQuery = graphql`
  query RootIntrusionSetQuery($id: String!) {
    intrusionSet(id: $id) {
      id
      name
      alias
      ...IntrusionSet_intrusionSet
      ...IntrusionSetReports_intrusionSet
      ...IntrusionSetKnowledge_intrusionSet
      ...IntrusionSetIndicators_intrusionSet
      ...FileImportViewer_entity
      ...FileExportViewer_entity
    }
    connectorsForExport {
      ...FileManager_connectorsExport
    }
  }
`;

class RootIntrusionSet extends Component {
  componentDidMount() {
    const {
      match: {
        params: { intrusionSetId },
      },
    } = this.props;
    const sub = requestSubscription({
      subscription,
      variables: { id: intrusionSetId },
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
        params: { intrusionSetId },
      },
    } = this.props;
    return (
      <div>
        <TopBar me={me || null} />
        <QueryRenderer
          query={intrusionSetQuery}
          variables={{ id: intrusionSetId }}
          render={({ props }) => {
            if (props && props.intrusionSet) {
              return (
                <div>
                  <Route
                    exact
                    path="/dashboard/threats/intrusion_sets/:intrusionSetId"
                    render={(routeProps) => (
                      <IntrusionSet
                        {...routeProps}
                        intrusionSet={props.intrusionSet}
                      />
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/threats/intrusion_sets/:intrusionSetId/reports"
                    render={(routeProps) => (
                      <IntrusionSetReports
                        {...routeProps}
                        intrusionSet={props.intrusionSet}
                      />
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/threats/intrusion_sets/:intrusionSetId/knowledge"
                    render={() => (
                      <Redirect
                        to={`/dashboard/threats/intrusion_sets/${intrusionSetId}/knowledge/overview`}
                      />
                    )}
                  />
                  <Route
                    path="/dashboard/threats/intrusion_sets/:intrusionSetId/knowledge"
                    render={(routeProps) => (
                      <IntrusionSetKnowledge
                        {...routeProps}
                        intrusionSet={props.intrusionSet}
                      />
                    )}
                  />
                  <Route
                    path="/dashboard/threats/intrusion_sets/:intrusionSetId/indicators"
                    render={(routeProps) => (
                      <IntrusionSetIndicators
                        {...routeProps}
                        intrusionSet={props.intrusionSet}
                      />
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/threats/intrusion_sets/:intrusionSetId/files"
                    render={(routeProps) => (
                      <React.Fragment>
                        <StixDomainEntityHeader
                          stixDomainEntity={props.intrusionSet}
                          PopoverComponent={<IntrusionSetPopover />}
                        />
                        <FileManager
                          {...routeProps}
                          id={intrusionSetId}
                          connectorsExport={props.connectorsForExport}
                          entity={props.intrusionSet}
                        />
                      </React.Fragment>
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/threats/intrusion_sets/:intrusionSetId/history"
                    render={(routeProps) => (
                      <React.Fragment>
                        <StixDomainEntityHeader
                          stixDomainEntity={props.intrusionSet}
                          PopoverComponent={<IntrusionSetPopover />}
                        />
                        <StixObjectHistory
                          {...routeProps}
                          entityId={intrusionSetId}
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

RootIntrusionSet.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootIntrusionSet);
