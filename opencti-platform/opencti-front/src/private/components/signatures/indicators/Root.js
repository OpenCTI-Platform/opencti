import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, withRouter } from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../relay/environment';
import TopBar from '../../nav/TopBar';
import StixRelation from '../../common/stix_relations/StixRelation';
import Indicator from './Indicator';
import IndicatorObservables from './IndicatorObservables';
import Loader from '../../../../components/Loader';
import StixObjectHistory from '../../common/stix_object/StixObjectHistory';
import IndicatorHeader from './IndicatorHeader';
import IndicatorPopover from './IndicatorPopover';

const subscription = graphql`
  subscription RootIndicatorSubscription($id: ID!) {
    stixDomainEntity(id: $id) {
      ... on Indicator {
        ...Indicator_indicator
        ...IndicatorEditionContainer_indicator
        ...IndicatorObservables_indicator
      }
    }
  }
`;

const indicatorQuery = graphql`
  query RootIndicatorQuery($id: String!) {
    indicator(id: $id) {
      id
      name
      alias
      ...Indicator_indicator
      ...IndicatorHeader_indicator
      ...IndicatorOverview_indicator
      ...IndicatorDetails_indicator
      ...IndicatorObservables_indicator
    }
  }
`;

class RootIndicator extends Component {
  componentDidMount() {
    const {
      match: {
        params: { indicatorId },
      },
    } = this.props;
    const sub = requestSubscription({
      subscription,
      variables: { id: indicatorId },
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
        params: { indicatorId },
      },
    } = this.props;
    return (
      <div>
        <TopBar me={me || null} />
        <QueryRenderer
          query={indicatorQuery}
          variables={{ id: indicatorId, relationType: 'indicates' }}
          render={({ props }) => {
            if (props && props.indicator) {
              return (
                <div>
                  <Route
                    exact
                    path="/dashboard/signatures/indicators/:indicatorId"
                    render={(routeProps) => (
                      <Indicator {...routeProps} indicator={props.indicator} />
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/signatures/indicators/:indicatorId/observables"
                    render={(routeProps) => (
                      <IndicatorObservables
                        {...routeProps}
                        indicator={props.indicator}
                      />
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/signatures/indicators/:indicatorId/history"
                    render={(routeProps) => (
                      <React.Fragment>
                        <IndicatorHeader
                          indicator={props.indicator}
                          PopoverComponent={<IndicatorPopover />}
                        />
                        <StixObjectHistory
                          {...routeProps}
                          entityId={indicatorId}
                        />
                      </React.Fragment>
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/signatures/indicators/:indicatorId/knowledge/relations/:relationId"
                    render={(routeProps) => (
                      <StixRelation entityId={indicatorId} {...routeProps} />
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

RootIndicator.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootIndicator);
