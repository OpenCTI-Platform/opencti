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
          path="/dashboard/vsac"
          render={() => <Redirect to="/dashboard/vsac/scans" />}
        />
         <BoundaryRoute
          exact
          path="/dashboard/vsac/scans/exploreresults"
          render={(routeProps) => (
            <ExploreResults {...routeProps} me={me} displayCreate={true} />
          )}
        />
        <BoundaryRoute
          exact
          path="/dashboard/vsac/scans/viewcharts"
          render={(routeProps) => (
            <ViewCharts {...routeProps} me={me} displayCreate={true} />
          )}
        />
        <BoundaryRoute
          exact
          path="/dashboard/vsac/scans/compare"
          render={(routeProps) => (
            <Compare {...routeProps} me={me} displayCreate={true} />
          )}
        />
        <BoundaryRoute
          exact
          path="/dashboard/vsac/scans"
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
