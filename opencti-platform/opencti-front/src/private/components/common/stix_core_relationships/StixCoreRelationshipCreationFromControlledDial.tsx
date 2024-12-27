import React, { FunctionComponent } from 'react';
import { CircularProgress } from '@mui/material';
import StixCoreRelationshipCreationFromControlledDialContent from '@components/common/stix_core_relationships/StixCoreRelationshipCreationFromControlledDialContent';
import { stixCoreRelationshipCreationFromEntityQuery } from './StixCoreRelationshipCreationFromEntity';
import { StixCoreRelationshipCreationFromEntityQuery } from './__generated__/StixCoreRelationshipCreationFromEntityQuery.graphql';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';

export const renderLoader = () => {
  return (
    <div style={{
      display: 'table',
      height: '100%',
      width: '100%',
    }}
    >
      <span style={{
        display: 'table-cell',
        verticalAlign: 'middle',
        textAlign: 'center',
      }}
      >
        <CircularProgress size={80} thickness={2}/>
      </span>
    </div>
  );
};

interface StixCoreRelationshipCreationFromControlledDialProps {
  entityId: string,
  defaultStartTime?: string,
  defaultStopTime?: string,
  controlledDial?: ({ onOpen }: { onOpen: () => void }) => React.ReactElement,
}

const StixCoreRelationshipCreationFromControlledDial: FunctionComponent<StixCoreRelationshipCreationFromControlledDialProps> = ({
  entityId,
  defaultStartTime,
  defaultStopTime,
  controlledDial,
}) => {
  const queryRef = useQueryLoading<StixCoreRelationshipCreationFromEntityQuery>(stixCoreRelationshipCreationFromEntityQuery, { id: entityId });
  if (queryRef) {
    return (
      <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
        <StixCoreRelationshipCreationFromControlledDialContent
          queryRef={queryRef}
          entityId={entityId}
          defaultStartTime={defaultStartTime}
          defaultStopTime={defaultStopTime}
          controlledDial={controlledDial}
        />
      </React.Suspense>
    );
  }
  return (
    <Loader variant={LoaderVariant.inElement} />
  );
};

export default StixCoreRelationshipCreationFromControlledDial;
