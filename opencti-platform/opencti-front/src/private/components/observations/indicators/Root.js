import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, withRouter } from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../relay/environment';
import TopBar from '../../nav/TopBar';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import Indicator from './Indicator';
import Loader from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import IndicatorHeader from './IndicatorHeader';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import IndicatorEntities from './IndicatorEntities';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import StixSightingRelationship from '../../events/stix_sighting_relationships/StixSightingRelationship';

const subscription = graphql`
  subscription RootIndicatorSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on Indicator {
        ...Indicator_indicator
        ...IndicatorEditionContainer_indicator
      }
    }
  }
`;

const indicatorQuery = graphql`
  query RootIndicatorQuery($id: String!) {
    indicator(id: $id) {
      id
      standard_id
      name
      ...Indicator_indicator
      ...IndicatorHeader_indicator
      ...IndicatorDetails_indicator
    }
  }
`;

class RootIndicator extends Component {
  constructor(props) {
    super(props);
    const {
      match: {
        params: { indicatorId },
      },
    } = props;
    this.sub = requestSubscription({
      subscription,
      variables: { id: indicatorId },
    });
  }

  componentWillUnmount() {
    this.sub.dispose();
  }

  render() {
    const {
      me,
      match: {
        params: { indicatorId },
      },
    } = this.props;
    return (
      <div>
        <TopBar me={me || null} />
        <QueryRenderer
          query={indicatorQuery}
          variables={{ id: indicatorId, relationship_type: 'indicates' }}
          render={({ props }) => {
            if (props) {
              if (props.indicator) {
                return (
                  <div>
                    <Route
                      exact
                      path="/dashboard/observations/indicators/:indicatorId"
                      render={(routeProps) => (
                        <Indicator
                          {...routeProps}
                          indicator={props.indicator}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/observations/indicators/:indicatorId/sightings"
                      render={(routeProps) => (
                        <React.Fragment>
                          <IndicatorHeader indicator={props.indicator} />
                          <EntityStixSightingRelationships
                            {...routeProps}
                            entityId={indicatorId}
                            noPadding={true}
                            targetStixDomainObjectTypes={[
                              'Region',
                              'Country',
                              'City',
                              'Organization',
                              'User',
                            ]}
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/observations/indicators/:indicatorId/history"
                      render={(routeProps) => (
                        <React.Fragment>
                          <IndicatorHeader indicator={props.indicator} />
                          <StixCoreObjectHistory
                            {...routeProps}
                            stixCoreObjectId={indicatorId}
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/observations/indicators/:indicatorId/knowledge"
                      render={(routeProps) => (
                        <React.Fragment>
                          <IndicatorHeader indicator={props.indicator} />
                          <IndicatorEntities
                            {...routeProps}
                            indicatorId={indicatorId}
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/observations/indicators/:indicatorId/knowledge/relations/:relationId"
                      render={(routeProps) => (
                        <StixCoreRelationship
                          entityId={indicatorId}
                          {...routeProps}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/observations/indicators/:indicatorId/knowledge/sightings/:sightingId"
                      render={(routeProps) => (
                        <StixSightingRelationship
                          entityId={indicatorId}
                          {...routeProps}
                        />
                      )}
                    />
                  </div>
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

RootIndicator.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootIndicator);
