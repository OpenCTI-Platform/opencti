import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Drawer, { DrawerVariant } from '@components/common/drawer/Drawer';
import { CaseRfiEditionOverview_case$key } from '@components/cases/case_rfis/__generated__/CaseRfiEditionOverview_case.graphql';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import { useFormatter } from '../../../../components/i18n';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import { CaseRfiEditionContainerCaseQuery } from './__generated__/CaseRfiEditionContainerCaseQuery.graphql';
import CaseRfiEditionOverview from './CaseRfiEditionOverview';
import CaseRfiDelete from './CaseRfiDelete';

interface CaseRfiEditionContainerProps {
  queryRef: PreloadedQuery<CaseRfiEditionContainerCaseQuery>
  handleClose: () => void
  controlledDial?: (({ onOpen, onClose }: {
    onOpen: () => void;
    onClose: () => void;
  }) => React.ReactElement<unknown, string | React.JSXElementConstructor<unknown>>)
  open?: boolean
}

export const caseRfiEditionQuery = graphql`
  query CaseRfiEditionContainerCaseQuery($id: String!) {
    caseRfi(id: $id) {
      id
      ...CaseRfiEditionOverview_case
      editContext {
        name
        focusOn
      }
    }
  }
`;

const CaseRfiEditionContainer: FunctionComponent<CaseRfiEditionContainerProps> = ({
  queryRef,
  handleClose,
  controlledDial,
  open,
}) => {
  const { t_i18n } = useFormatter();
  const { caseRfi } = usePreloadedQuery(caseRfiEditionQuery, queryRef);
  if (caseRfi === null) {
    return <ErrorNotFound />;
  }
  return (
    <Drawer
      title={t_i18n('Update a request for information')}
      variant={open == null && controlledDial === null
        ? DrawerVariant.update
        : undefined}
      context={caseRfi?.editContext}
      onClose={handleClose}
      open={open}
      controlledDial={controlledDial}
    >
      {({ onClose }) => (<>
        <CaseRfiEditionOverview
          caseRef={caseRfi as CaseRfiEditionOverview_case$key}
          context={caseRfi?.editContext}
          enableReferences={useIsEnforceReference('Case-Rfi')}
          handleClose={onClose}
        />
        {!useIsEnforceReference('Case-Rfi') && caseRfi?.id
          && <CaseRfiDelete id={caseRfi.id} />
        }
      </>)}
    </Drawer>
  );
};

export default CaseRfiEditionContainer;
