import React, { FunctionComponent } from 'react';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { GroupEditionContainerQuery } from './__generated__/GroupEditionContainerQuery.graphql';
import GroupEditionContainer, { groupEditionContainerQuery } from './GroupEditionContainer';

interface GroupEditionProps {
  handleClose?: () => void
  groupId: string
  open?: boolean
  disabled?: boolean
  isSensitive?: boolean
}

const GroupEdition: FunctionComponent<GroupEditionProps> = ({
  handleClose,
  groupId,
  open,
  disabled = false,
  isSensitive = false,
}) => {
  const groupQueryRef = useQueryLoading<GroupEditionContainerQuery>(groupEditionContainerQuery, { id: groupId });
  return (
    <div>
      {groupQueryRef && (
        <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <GroupEditionContainer
            groupQueryRef={groupQueryRef}
            handleClose={handleClose}
            open={open}
            disabled={disabled}
            isSensitive={isSensitive}
          />
        </React.Suspense>
      )}
    </div>
  );
};

export default GroupEdition;
