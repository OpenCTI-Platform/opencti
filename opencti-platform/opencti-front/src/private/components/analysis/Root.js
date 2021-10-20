import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Switch, Redirect } from 'react-router-dom';
import { BoundaryRoute } from '../Error';
import Reports from './Reports';
import RootReport from './reports/Root';
import Notes from './Notes';
import RootNote from './notes/Root';
import Opinions from './Opinions';
import RootOpinion from './opinions/Root';
import ExternalReferences from './ExternalReferences';
import RootExternalReference from './external_references/Root';

class Root extends Component {
  render() {
    const { me } = this.props;
    return (
      <Switch>
        <BoundaryRoute
          exact
          path="/dashboard/analysis"
          render={() => <Redirect to="/dashboard/analysis/reports" />}
        />
        <BoundaryRoute
          exact
          path="/dashboard/analysis/reports"
          render={(routeProps) => (
            <Reports {...routeProps} me={me} displayCreate={true} />
          )}
        />
        <BoundaryRoute
          path="/dashboard/analysis/reports/:reportId"
          render={(routeProps) => <RootReport {...routeProps} me={me} />}
        />
        <BoundaryRoute
          exact
          path="/dashboard/analysis/notes"
          component={Notes}
        />
        <BoundaryRoute
          path="/dashboard/analysis/notes/:noteId"
          render={(routeProps) => <RootNote {...routeProps} me={me} />}
        />
        <BoundaryRoute
          exact
          path="/dashboard/analysis/opinions"
          component={Opinions}
        />
        <BoundaryRoute
          path="/dashboard/analysis/opinions/:opinionId"
          render={(routeProps) => <RootOpinion {...routeProps} me={me} />}
        />
        <BoundaryRoute
          exact
          path="/dashboard/analysis/external_references"
          component={ExternalReferences}
        />
        <BoundaryRoute
          path="/dashboard/analysis/external_references/:externalReferenceId"
          render={(routeProps) => (
            <RootExternalReference {...routeProps} me={me} />
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
