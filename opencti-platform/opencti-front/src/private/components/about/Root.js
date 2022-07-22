import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Switch, Redirect } from 'react-router-dom';
import { BoundaryRoute } from '../Error';
import About from './About';
import HowTo from './HowTo';

class Root extends Component {
  render() {
    const { me } = this.props;
    return (
      <Switch>
        <BoundaryRoute
          exact
          path="/about"
          render={() => <Redirect to="/about/entities" />}
        />
        <BoundaryRoute
          exact
          path="/about/entities"
          component={About}
        />
        <BoundaryRoute
          exact
          path="/about/entities/how_to"
          component={HowTo}
        />
        <BoundaryRoute
          exact
          path="/about/entities/index"
          component={HowTo}
        />
        <BoundaryRoute
          exact
          path="/about/entities/glossary"
          component={HowTo}
        />
        <BoundaryRoute
          exact
          path="/about/entities/release_note"
          component={HowTo}
        />
        <BoundaryRoute
          exact
          path="/about/entities/faq"
          component={HowTo}
        />
        <BoundaryRoute
          exact
          path="/about/entities/contact_us"
          component={HowTo}
        />
      </Switch>
    );
  }
}

Root.propTypes = {
  me: PropTypes.object,
};

export default Root;
