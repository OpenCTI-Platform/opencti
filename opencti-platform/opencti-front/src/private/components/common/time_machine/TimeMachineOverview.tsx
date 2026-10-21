import React, { ReactNode } from 'react';
import SinceLastVisitChips from './SinceLastVisitChips';

interface TimeMachineOverviewProps {
  entityId: string;
  // Path of the Changes tab of the entity, when it has one
  changesPath?: string;
  children: ReactNode;
}

/**
 * Overview of an entity with what is new since the last visit of the user.
 * The views of the entity at past dates live in its Changes tab.
 */
const TimeMachineOverview = ({ entityId, changesPath, children }: TimeMachineOverviewProps) => (
  <>
    <SinceLastVisitChips entityId={entityId} changesPath={changesPath} />
    {children}
  </>
);

export default TimeMachineOverview;
