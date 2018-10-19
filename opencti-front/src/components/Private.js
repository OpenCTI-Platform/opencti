import React, {Component} from "react";
import {QueryRenderer} from "react-relay";
import environment from "../relay/environment";
import graphql from "babel-plugin-relay/macro";
import Cookies from "universal-cookie";

const testQuery = graphql`
    query PrivateUserQuery {
        me {
            email
            roles
        }
    }
`;


class Private extends Component {

    static callLogout() {
        //Call graphQL mutation logout to remove the token
        new Cookies().remove('opencti_token');
    }

    render() {
        return (
            <div>
                <h2>Private</h2>
                <QueryRenderer
                    environment={environment}
                    query={testQuery}
                    variables={{}}
                    render={({error, props}) => {
                        if (error) {
                            return <div>Error! {error}</div>;
                        }
                        if (!props || !props.me) {
                            return <div>Loading...</div>;
                        }
                        return <div>
                            <div>
                                Yop {props.me.email}
                            </div>
                            <div><button onClick={Private.callLogout}>Logout</button></div>
                        </div>
                    }}
                />
            </div>
        )
    }
}

export default Private;