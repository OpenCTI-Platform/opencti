import React, { ReactNode } from 'react';
import SinceLastVisitChips from './SinceLastVisitChips';

interface TimeMachineOverviewProps {
  entityId: string;
  children: ReactNode;
}

/**
 * Overview of an entity with what is new since the last visit of the user.
 * The views of the entity at past dates live in its Changes tab.
 */
const TimeMachineOverview = ({ entityId, children }: TimeMachineOverviewProps) => (
  <>
    <SinceLastVisitChips entityId={entityId} />
    {children}
  </>
);

export default TimeMachineOverview;
