import React from 'react';
import { compose, includes, map } from 'ramda';
import * as PropTypes from 'prop-types';
import { withRouter } from 'react-router-dom';
import LoginRoot from '../../public/LoginRoot';

class AuthBoundaryComponent extends React.Component {
  constructor(props) {
    super(props);
    this.state = { error: null, stack: null };
  }

  componentDidCatch(error, stack) {
    this.setState({ error, stack });
  }

  render() {
    if (this.state.error) {
      const baseErrors = this.state.error.res?.errors ?? [];
      const retroErrors = this.state.error.data?.res?.errors ?? [];
      const types = map((e) => e.name, [...baseErrors, ...retroErrors]);
      // If access is forbidden, just redirect to home page
      if (includes('ForbiddenAccess', types)) {
        return <LoginRoot type="LOGIN" />;
        // window.location.href = '/';
      }
      // If user not authenticated, redirect to login with encoded path
      if (includes('AuthRequired', types)) {
        return <LoginRoot type="LOGIN" />;
      }
      if (includes('OtpRequiredActivation', types)) {
        return <LoginRoot type="2FA_ACTIVATION" />;
      }
      if (includes('OtpRequired', types)) {
        return <LoginRoot type="2FA_VALIDATION" />;
      }
    }
    return this.props.children;
  }
}
AuthBoundaryComponent.propTypes = {
  children: PropTypes.node,
};
export default compose(withRouter)(AuthBoundaryComponent);
