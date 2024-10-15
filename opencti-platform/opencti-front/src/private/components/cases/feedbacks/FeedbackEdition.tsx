import React, { FunctionComponent } from 'react';
import EditEntityControlledDial from '../../../../components/EditEntityControlledDial';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { feedbackEditionOverviewFocus } from './FeedbackEditionOverview';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import FeedbackEditionContainer, { feedbackEditionQuery } from './FeedbackEditionContainer';
import { FeedbackEditionContainerQuery } from './__generated__/FeedbackEditionContainerQuery.graphql';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

const FeedbackEdition: FunctionComponent<{ feedbackId: string }> = ({ feedbackId }) => {
  const [commit] = useApiMutation(feedbackEditionOverviewFocus);
  const handleClose = () => {
    commit({
      variables: {
        id: feedbackId,
        input: { focusOn: '' },
      },
    });
  };
  const queryRef = useQueryLoading<FeedbackEditionContainerQuery>(
    feedbackEditionQuery,
    { id: feedbackId },
  );
  return (
    <>
      {queryRef && (
        <React.Suspense
          fallback={<Loader variant={LoaderVariant.inline} />}
        >
          <FeedbackEditionContainer
            queryRef={queryRef}
            handleClose={handleClose}
            controlledDial={EditEntityControlledDial}
          />
        </React.Suspense>
      )}
    </>
  );
};

export default FeedbackEdition;
