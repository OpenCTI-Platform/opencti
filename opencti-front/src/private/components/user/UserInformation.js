import React, {Component} from "react";
import {createFragmentContainer} from "react-relay";
import graphql from "babel-plugin-relay/macro";

class UserInformation extends Component {
    render() {
        const me = this.props.me;
        return <span><b>{me.email}</b> ({me.username})</span>
    }
}

export default createFragmentContainer(UserInformation, {
    me: graphql`
        fragment UserInformation_me on User {
            email,
            username
        }
    `,
});