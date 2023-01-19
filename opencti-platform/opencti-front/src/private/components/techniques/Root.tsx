/* eslint-disable @typescript-eslint/no-explicit-any */
// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React from 'react';
import { Redirect, Switch } from 'react-router-dom';
import { BoundaryRoute } from '../Error';
import AttackPatterns from './AttackPatterns';
import RootAttackPattern from './attack_patterns/Root';
import Narratives from './Narratives';
import RootNarrative from './narratives/Root';
import CoursesOfAction from './CoursesOfAction';
import RootCourseOfAction from './courses_of_action/Root';
import DataComponents from './DataComponents';
import RootDataComponent from './data_components/Root';
import RootDataSource from './data_sources/Root';
import DataSources from './DataSources';
import { useIsHiddenEntity } from '../../../utils/hooks/useEntitySettings';

const Root = () => {
  let redirect: string | null = null;
  if (!useIsHiddenEntity('Attack-Pattern')) {
    redirect = 'attack_patterns';
  } else if (!useIsHiddenEntity('Narrative')) {
    redirect = 'narratives';
  } else if (!useIsHiddenEntity('Course-Of-Action')) {
    redirect = 'courses_of_action';
  } else if (!useIsHiddenEntity('Data-Component')) {
    redirect = 'data_components';
  } else if (!useIsHiddenEntity('Data-Source')) {
    redirect = 'data_sources';
  }
  return (
    <Switch>
      <BoundaryRoute
        exact
        path="/dashboard/techniques"
        render={() => <Redirect to={`/dashboard/techniques/${redirect}`} />}
      />
      <BoundaryRoute
        exact
        path="/dashboard/techniques/attack_patterns"
        component={AttackPatterns}
      />
      <BoundaryRoute
        path="/dashboard/techniques/attack_patterns/:attackPatternId"
        component={RootAttackPattern}
      />
      <BoundaryRoute
        exact
        path="/dashboard/techniques/narratives"
        component={Narratives}
      />
      <BoundaryRoute
        path="/dashboard/techniques/narratives/:narrativeId"
        component={RootNarrative}
      />
      <BoundaryRoute
        exact
        path="/dashboard/techniques/courses_of_action"
        component={CoursesOfAction}
      />
      <BoundaryRoute
        path="/dashboard/techniques/courses_of_action/:courseOfActionId"
        component={RootCourseOfAction}
      />
      <BoundaryRoute
        exact
        path="/dashboard/techniques/data_components"
        component={DataComponents}
      />
      <BoundaryRoute
        path="/dashboard/techniques/data_components/:dataComponentId"
        component={RootDataComponent}
      />
      <BoundaryRoute
        exact
        path="/dashboard/techniques/data_sources"
        component={DataSources}
      />
      <BoundaryRoute
        path="/dashboard/techniques/data_sources/:dataSourceId"
        component={RootDataSource}
      />
    </Switch>
  );
};

export default Root;
