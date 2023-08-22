/*
Copyright (c) 2021-2023 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Non-Commercial License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, withRouter } from 'react-router-dom';
import { graphql } from 'react-relay';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../relay/environment';
import Playbook from './Playbook';
import Loader from '../../../../components/Loader';
import ErrorNotFound from '../../../../components/ErrorNotFound';

const subscription = graphql`
  subscription RootPlaybookSubscription($id: ID!) {
    internalObject(id: $id) {
      ... on Playbook {
        ...Playbook_playbook
      }
    }
  }
`;

const playbookQuery = graphql`
  query RootPlaybookQuery($id: String!) {
    playbook(id: $id) {
      id
      ...Playbook_playbook
    }
  }
`;

class RootPlaybook extends Component {
  constructor(props) {
    super(props);
    const {
      match: {
        params: { playbookId },
      },
    } = props;
    this.sub = requestSubscription({
      subscription,
      variables: { id: playbookId },
    });
  }e

  componentWillUnmount() {
    this.sub.dispose();
  }

  render() {
    const {
      match: {
        params: { playbookId },
      },
    } = this.props;
    return (
      <QueryRenderer
        query={playbookQuery}
        variables={{ id: playbookId }}
        render={({ props }) => {
          if (props) {
            if (props.playbook) {
              return (
                <>
                  <Route
                    exact
                    path="/dashboard/data/processing/automation/:playbookId"
                    render={(routeProps) => (
                      <Playbook {...routeProps} playbook={props.playbook} />
                    )}
                  />
                </>
              );
            }
            return <ErrorNotFound />;
          }
          return <Loader />;
        }}
      />
    );
  }
}

RootPlaybook.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
};

export default withRouter(RootPlaybook);
