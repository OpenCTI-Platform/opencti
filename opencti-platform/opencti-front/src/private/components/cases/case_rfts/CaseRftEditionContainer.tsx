import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Drawer, { DrawerVariant } from '@components/common/drawer/Drawer';
import { CaseRftEditionOverview_case$key } from '@components/cases/case_rfts/__generated__/CaseRftEditionOverview_case.graphql';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import { useFormatter } from '../../../../components/i18n';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import { CaseRftEditionContainerCaseQuery } from './__generated__/CaseRftEditionContainerCaseQuery.graphql';
import CaseRftEditionOverview from './CaseRftEditionOverview';
import CaseRftDelete from './CaseRftDelete';

interface CaseRftEditionContainerProps {
  queryRef: PreloadedQuery<CaseRftEditionContainerCaseQuery>
  handleClose: () => void
  controlledDial?: (({ onOpen, onClose }: {
    onOpen: () => void;
    onClose: () => void;
  }) => React.ReactElement<unknown, string | React.JSXElementConstructor<unknown>>)
  open?: boolean
}

export const caseRftEditionQuery = graphql`
  query CaseRftEditionContainerCaseQuery($id: String!) {
    caseRft(id: $id) {
      id
      ...CaseRftEditionOverview_case
      editContext {
        name
        focusOn
      }
    }
  }
`;

const CaseRftEditionContainer: FunctionComponent<CaseRftEditionContainerProps> = ({
  queryRef,
  handleClose,
  controlledDial,
  open,
}) => {
  const { t_i18n } = useFormatter();
  const { caseRft } = usePreloadedQuery(caseRftEditionQuery, queryRef);
  if (caseRft === null) {
    return <ErrorNotFound />;
  }
  return (
    <Drawer
      title={t_i18n('Update a request for takedown')}
      variant={open == null && controlledDial === null
        ? DrawerVariant.update
        : undefined}
      context={caseRft?.editContext}
      onClose={handleClose}
      open={open}
      controlledDial={controlledDial}
    >
      {({ onClose }) => (<>
        <CaseRftEditionOverview
          caseRef={caseRft as CaseRftEditionOverview_case$key}
          context={caseRft?.editContext}
          enableReferences={useIsEnforceReference('Case-Rft')}
          handleClose={onClose}
        />
        {!useIsEnforceReference('Case-Rft') && caseRft?.id
          && <CaseRftDelete id={caseRft.id} />
        }
      </>)}
    </Drawer>
  );
};

export default CaseRftEditionContainer;
