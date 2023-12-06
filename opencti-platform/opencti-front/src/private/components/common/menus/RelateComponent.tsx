import React, { FunctionComponent, useContext, useState } from 'react';
import Security from 'src/utils/Security';
import { KNOWLEDGE_KNUPDATE } from 'src/utils/hooks/useGranted';
import { computeTargetStixCyberObservableTypes, computeTargetStixDomainObjectTypes } from 'src/utils/stixTypeUtils';
import StixCoreRelationshipCreationFromEntity from '../stix_core_relationships/StixCoreRelationshipCreationFromEntity';
import CreateRelationshipControlledDial from './CreateRelationshipControlledDial';
import { RelateComponentContext } from './RelateComponentProvider';

interface CreateRelationshipButtonComponentProps {
  id: string
  defaultStartTime: Date
  defaultStopTime: Date
  onCreate?: () => void
}

const CreateRelationshipButtonComponent: FunctionComponent<CreateRelationshipButtonComponentProps> = ({
  id,
  defaultStartTime,
  defaultStopTime,
  onCreate,
}) => {
  const [reversed, setReversed] = useState<boolean>(false);
  const { stixCoreObjectTypes } = useContext(RelateComponentContext);
  return (
    <Security needs={[KNOWLEDGE_KNUPDATE]}>
      <StixCoreRelationshipCreationFromEntity
        entityId={id}
        isRelationReversed={reversed}
        targetStixDomainObjectTypes={computeTargetStixDomainObjectTypes(
          stixCoreObjectTypes,
        )}
        targetStixCyberObservableTypes={computeTargetStixCyberObservableTypes(
          stixCoreObjectTypes,
        )}
        handleReverseRelation={() => setReversed(!reversed)}
        defaultStartTime={new Date(defaultStartTime).toISOString()}
        defaultStopTime={new Date(defaultStopTime).toISOString()}
        paginationOptions={{}}
        connectionKey="Pagination_stixCoreObjects"
        paddingRight={0}
        onCreate={onCreate ?? (() => {})}
        controlledDial={CreateRelationshipControlledDial}
      />
    </Security>
  );
};

export default CreateRelationshipButtonComponent;
