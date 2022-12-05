/* eslint-disable */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Switch, Redirect } from 'react-router-dom';
import { BoundaryRoute } from '../Error';
import Scans from './Scans';
import ExploreResults from './ExploreResults';
import ViewCharts from './ViewCharts';
import Compare from './Compare';


class Root extends Component {
  render() {
    const { me } = this.props;
    return (
      <Switch>
        <BoundaryRoute
          exact
          path="/activities/vulnerability_assessment"
          render={() => <Redirect to="/activities/vulnerability_assessment/scans" />}
        />
         <BoundaryRoute
          exact
          path="/activities/vulnerability_assessment/scans/explore results/:exploreResultId"
          render={(routeProps) => (
            <ExploreResults {...routeProps} me={me} displayCreate={true} />
          )}
        />
        <BoundaryRoute
          exact
          path="/activities/vulnerability_assessment/scans/view charts"
          render={(routeProps) => (
            <ViewCharts {...routeProps} me={me} displayCreate={true} />
          )}
        />
        <BoundaryRoute
          exact
          path="/activities/vulnerability_assessment/scans/compare analysis"
          render={(routeProps) => (
            <Compare {...routeProps} me={me} displayCreate={true} />
          )}
        />
        <BoundaryRoute
          exact
          path="/activities/vulnerability_assessment/scans"
          render={(routeProps) => (
            <Scans {...routeProps} me={me} displayCreate={true} />
          )}
        />
      </Switch>
    );
  }
}

Root.propTypes = {
  me: PropTypes.object,
};

export default Root;
