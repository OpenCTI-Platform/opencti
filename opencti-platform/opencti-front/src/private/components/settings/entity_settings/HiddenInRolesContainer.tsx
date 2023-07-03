import React, { FunctionComponent } from 'react';
import { HiddenInRolesQuery } from './__generated__/HiddenInRolesQuery.graphql';
import HiddenInRoles, { hiddenInRolesQuery } from './HiddenInRoles';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';

interface HiddenInRolesProps {
  targetTypes: string[],
  platformHiddenTargetType: string,
}

const HiddenInRolesContainer: FunctionComponent<HiddenInRolesProps> = ({ targetTypes, platformHiddenTargetType }) => {
  const queryRef = useQueryLoading<HiddenInRolesQuery>(hiddenInRolesQuery, {});

  return (
    <div>
    {queryRef && (
      <React.Suspense
        fallback={<Loader variant={LoaderVariant.inElement} />}
      >
        <HiddenInRoles queryRef={queryRef} targetTypes={targetTypes} platformHiddenTargetType={platformHiddenTargetType} />
      </React.Suspense>)
    }
    </div>
  );
};

export default HiddenInRolesContainer;
