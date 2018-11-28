import React, { Component } from 'react';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import * as PropTypes from 'prop-types';

class UserInformation extends Component {
  render() {
    const { me } = this.props;
    return <span>&nbsp;{me.email} ({me.username})</span>;
  }
}

UserInformation.propTypes = {
  me: PropTypes.object,
};

export default createFragmentContainer(UserInformation, {
  me: graphql`
        fragment UserInformation_me on User {
            email,
            username
        }
    `,
});
