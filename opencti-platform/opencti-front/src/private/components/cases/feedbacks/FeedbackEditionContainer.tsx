import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Drawer, { DrawerVariant } from '@components/common/drawer/Drawer';
import { FeedbackEditionOverview_case$key } from '@components/cases/feedbacks/__generated__/FeedbackEditionOverview_case.graphql';
import { useFormatter } from '../../../../components/i18n';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import FeedbackEditionOverview from './FeedbackEditionOverview';
import { FeedbackEditionContainerQuery } from './__generated__/FeedbackEditionContainerQuery.graphql';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import FeedbackDelete from './FeedbackDelete';

interface FeedbackEditionContainerProps {
  queryRef: PreloadedQuery<FeedbackEditionContainerQuery>
  handleClose: () => void
  controlledDial?: (({ onOpen, onClose }: {
    onOpen: () => void;
    onClose: () => void;
  }) => React.ReactElement<unknown, string | React.JSXElementConstructor<unknown>>)
  open?: boolean
}

export const feedbackEditionQuery = graphql`
  query FeedbackEditionContainerQuery($id: String!) {
    feedback(id: $id) {
      id
      ...FeedbackEditionOverview_case
      editContext {
        name
        focusOn
      }
    }
  }
`;

const FeedbackEditionContainer: FunctionComponent<FeedbackEditionContainerProps> = ({
  queryRef,
  handleClose,
  controlledDial,
  open,
}) => {
  const { t_i18n } = useFormatter();
  const { feedback } = usePreloadedQuery(feedbackEditionQuery, queryRef);
  if (feedback === null) {
    return <ErrorNotFound />;
  }
  return (
    <Drawer
      title={t_i18n('Update a feedback')}
      variant={open == null && controlledDial === null
        ? DrawerVariant.update
        : undefined}
      context={feedback?.editContext}
      onClose={handleClose}
      open={open}
      controlledDial={controlledDial}
    >
      {({ onClose }) => (<>
        <FeedbackEditionOverview
          feedbackRef={feedback as FeedbackEditionOverview_case$key}
          context={feedback?.editContext}
          handleClose={onClose}
          enableReferences={useIsEnforceReference('Feedback')}
        />
        {!useIsEnforceReference('Feedback') && feedback?.id
          && <FeedbackDelete id={feedback.id} />
        }
      </>)}
    </Drawer>
  );
};

export default FeedbackEditionContainer;
