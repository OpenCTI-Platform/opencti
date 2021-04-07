import { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withRouter } from 'react-router-dom';
import { MESSAGING$ } from '../relay/environment';

class RedirectManager extends Component {
  componentDidMount() {
    this.subscription = MESSAGING$.redirect.subscribe({
      next: (url) => this.props.history.push(url),
    });
  }

  componentWillUnmount() {
    this.subscription.unsubscribe();
  }

  render() {
    return this.props.children;
  }
}
RedirectManager.propTypes = {
  history: PropTypes.object,
  children: PropTypes.node,
};

export default compose(withRouter)(RedirectManager);
