/* eslint-disable */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Switch } from 'react-router-dom';
import Faq from './Faq';
import About from './About';
import HowTo from './HowTo';
import Index from './Index';
import Glossary from './Glossary';
import ContactUs from './ContactUs';
import ReleaseNote from './ReleaseNote';
import { BoundaryRoute } from '../Error';

class Root extends Component {
  render() {
    // const { me } = this.props;
    return (
      <Switch>
        <BoundaryRoute
          exact
          path="/about"
          component={About}
        />
        <BoundaryRoute
          exact
          path="/about/how_to"
          component={HowTo}
        />
        <BoundaryRoute
          exact
          path="/about/index"
          component={Index}
        />
        <BoundaryRoute
          exact
          path="/about/glossary"
          component={Glossary}
        />
        <BoundaryRoute
          exact
          path="/about/release_note"
          component={ReleaseNote}
        />
        <BoundaryRoute
          exact
          path="/about/faq"
          component={Faq}
        />
        <BoundaryRoute
          exact
          path="/about/contact_us"
          component={ContactUs}
        />
      </Switch>
    );
  }
}

Root.propTypes = {
  me: PropTypes.object,
};

export default Root;
