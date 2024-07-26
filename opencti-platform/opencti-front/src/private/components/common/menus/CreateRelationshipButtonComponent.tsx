import React, { FunctionComponent } from 'react';
import Security from 'src/utils/Security';
import { KNOWLEDGE_KNUPDATE } from 'src/utils/hooks/useGranted';
import StixCoreRelationshipCreationFromControlledDial from '../stix_core_relationships/StixCoreRelationshipCreationFromControlledDial';

interface CreateRelationshipButtonComponentProps {
  id: string,
  defaultStartTime?: string | number | Date,
  defaultStopTime?: string | number | Date,
}

const CreateRelationshipButtonComponent: FunctionComponent<CreateRelationshipButtonComponentProps> = ({
  id,
  defaultStartTime,
  defaultStopTime,
}) => {
  const startTime = new Date(defaultStartTime ?? new Date()).toISOString();
  const stopTime = new Date(defaultStopTime ?? new Date()).toISOString();
  return (
    <Security needs={[KNOWLEDGE_KNUPDATE]}>
      <StixCoreRelationshipCreationFromControlledDial
        id={id}
        defaultStartTime={startTime}
        defaultStopTime={stopTime}
      />
    </Security>
  );
};

export default CreateRelationshipButtonComponent;
