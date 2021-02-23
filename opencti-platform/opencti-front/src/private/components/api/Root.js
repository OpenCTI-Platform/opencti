import React from 'react';
import { Switch } from 'react-router-dom';
import { BoundaryRoute } from '../Error';
import Taxii from './Taxii';

const RootApi = () => (
  <Switch>
    <BoundaryRoute exact path="/dashboard/api/taxii" component={Taxii} />
  </Switch>
);

export default RootApi;
