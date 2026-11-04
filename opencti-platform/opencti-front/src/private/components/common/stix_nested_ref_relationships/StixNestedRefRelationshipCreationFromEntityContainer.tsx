import React, { FunctionComponent } from 'react';
import StixNestedRefRelationshipCreationFromEntity, { stixNestedRefRelationResolveTypes } from './StixNestedRefRelationshipCreationFromEntity';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';

interface StixNestedRefRelationshipCreationFromEntityContainerProps {
  entityId: string;
  entityType: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  paginationOptions: any; // FIXME find the right type
}

const StixNestedRefRelationshipCreationFromEntityContainer: FunctionComponent<StixNestedRefRelationshipCreationFromEntityContainerProps> = ({
  entityId,
  entityType,
  paginationOptions,
}) => {
  const queryRef = useQueryLoading(stixNestedRefRelationResolveTypes, { type: entityType });
  return (
    <>
      {queryRef && (
        <React.Suspense
          fallback={<Loader variant={LoaderVariant.inline} />}
        >
          <StixNestedRefRelationshipCreationFromEntity
            possibleTypesQueryRef={queryRef}
            entityId={entityId}
            entityType={entityType}
            paginationOptions={paginationOptions}
          />
        </React.Suspense>
      )}
    </>
  );
};

export default StixNestedRefRelationshipCreationFromEntityContainer;
