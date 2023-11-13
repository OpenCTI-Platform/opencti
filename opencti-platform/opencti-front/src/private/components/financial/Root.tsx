/* eslint-disable @typescript-eslint/no-explicit-any */
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import { Redirect, Switch } from 'react-router-dom';
import { BoundaryRoute } from '../Error';
import Accounts from './Accounts';
import RootAccount from './accounts/Root';

const Root = () => (
  <Switch>
    <BoundaryRoute
      exact
      path="/dashboard/financial"
      render={() => <Redirect to="/dashboard/financial/accounts" />}
    />
    <BoundaryRoute
      exact
      path="/dashboard/financial/accounts"
      component={Accounts}
    />
    <BoundaryRoute
      path="/dashboard/financial/accounts/:accountId"
      component={RootAccount}
    />
  </Switch>
);

export default Root;
