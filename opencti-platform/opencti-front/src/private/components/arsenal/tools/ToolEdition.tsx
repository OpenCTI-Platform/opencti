import React, { FunctionComponent } from 'react';
import { ToolEditionContainerQuery } from '@components/arsenal/tools/__generated__/ToolEditionContainerQuery.graphql';
import ToolEditionContainer, { toolEditionQuery } from './ToolEditionContainer';
import { toolEditionOverviewFocus } from './ToolEditionOverview';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import EditEntityControlledDial from '../../../../components/EditEntityControlledDial';

const ToolEdition: FunctionComponent<{ toolId: string }> = ({ toolId }) => {
  const [commit] = useApiMutation(toolEditionOverviewFocus);

  const handleClose = () => {
    commit({
      variables: {
        id: toolId,
        input: { focusOn: '' },
      },
    });
  };

  const queryRef = useQueryLoading<ToolEditionContainerQuery>(toolEditionQuery, { id: toolId });

  return (
    <>
      {queryRef && (
      <React.Suspense fallback={<Loader variant={LoaderVariant.inline} />}>
        <ToolEditionContainer
          queryRef={queryRef}
          handleClose={handleClose}
          controlledDial={EditEntityControlledDial}
        />
      </React.Suspense>
      )
        }
    </>
  );
};

export default ToolEdition;
