/* eslint-disable @typescript-eslint/no-explicit-any */
// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React from 'react';
import { Route, Switch, useParams } from 'react-router-dom';
import { graphql } from 'react-relay';
import DecayRule from './DecayRule';
import { QueryRenderer } from '../../../../relay/environment';
import Loader from '../../../../components/Loader';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import { RootDecayRuleQuery$data } from './__generated__/RootDecayRuleQuery.graphql';

export const decayRuleQuery = graphql`
  query RootDecayRuleQuery($id: String!) {
    decayRule(id: $id) {
      ...DecayRule_decayRule
    }
  }
`;

const RootDecayRule = () => {
  const { decayRuleId } = useParams() as { decayRuleId: string };
  return (
    <QueryRenderer
      query={decayRuleQuery}
      variables={{ id: decayRuleId }}
      render={({ props }: { props: RootDecayRuleQuery$data }) => {
        if (props) {
          if (props.decayRule) {
            return (
              <Switch>
                <Route
                  exact
                  path="/dashboard/settings/customization/decay/:decayRuleId"
                  render={() => <DecayRule data={props.decayRule} />}
                />
              </Switch>
            );
          }
          return <ErrorNotFound />;
        }
        return <Loader />;
      }}
    />
  );
};

export default RootDecayRule;
