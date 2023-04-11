import React, { FunctionComponent } from 'react';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import GroupEditionContainer, { groupEditionContainerQuery } from './GroupEditionContainer';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { GroupEditionContainerQuery } from './__generated__/GroupEditionContainerQuery.graphql';

interface GroupEditionProps {
  handleClose: () => void,
  groupId: string,
}

const GroupEdition: FunctionComponent<GroupEditionProps> = ({ handleClose, groupId }) => {
  const groupQueryRef = useQueryLoading<GroupEditionContainerQuery>(groupEditionContainerQuery, { id: groupId });
  return (
    <div>
      {groupQueryRef && (
        <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <GroupEditionContainer
            groupQueryRef={groupQueryRef}
            handleClose={handleClose}
          />
        </React.Suspense>
      )}
    </div>
  );
};

export default GroupEdition;
