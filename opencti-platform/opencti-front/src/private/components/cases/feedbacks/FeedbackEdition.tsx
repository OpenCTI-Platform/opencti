import React, { FunctionComponent } from 'react';
import { useMutation } from 'react-relay';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { feedbackEditionOverviewFocus } from './FeedbackEditionOverview';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import FeedbackEditionContainer, { feedbackEditionQuery } from './FeedbackEditionContainer';
import { FeedbackEditionContainerQuery } from './__generated__/FeedbackEditionContainerQuery.graphql';

const FeedbackEdition: FunctionComponent<{ feedbackId: string }> = ({ feedbackId }) => {
  const [commit] = useMutation(feedbackEditionOverviewFocus);
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
          fallback={<Loader variant={LoaderVariant.inElement} />}
        >
          <FeedbackEditionContainer
            queryRef={queryRef}
            handleClose={handleClose}
          />
        </React.Suspense>
      )}
    </>
  );
};

export default FeedbackEdition;
