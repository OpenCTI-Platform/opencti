import React from "react";
import environment from "../relay/environment";
import {QueryRenderer} from "react-relay";
import graphql from "babel-plugin-relay/macro";

const testQuery = graphql`
    query HomeUserQuery {
        me {
            id
        }
    }
`;

export const Home = () => (
    <div>
        <h2>Home</h2>
        <QueryRenderer
            environment={environment}
            query={testQuery}
            variables={{}}
            render={({error, props}) => {
                if (error) {
                    return <div>Error! {error}</div>;
                }
                if (!props) {
                    return <div>Loading...</div>;
                }
                return <div>User ID: {props.me.id}</div>;
            }}
        />
    </div>
);