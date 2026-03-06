import React, { FunctionComponent } from 'react';
import Drawer from '@components/common/drawer/Drawer';
import { graphql } from 'react-relay';
import EditEntityControlledDial from '../../../components/EditEntityControlledDial';
import DraftEditionOverview from '@components/drafts/DraftEditionOverview';
import { useFormatter } from '../../../components/i18n';
import { DraftRootFragment$data } from '@components/drafts/__generated__/DraftRootFragment.graphql';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import { DraftEditionFocusMutation } from '@components/drafts/__generated__/DraftEditionFocusMutation.graphql';

export const draftEditionFocus = graphql`
  mutation DraftEditionFocusMutation($id: ID! $input: EditContext!) {
    draftWorkspaceContextPatch(id: $id, input: $input) {
      id
    }
  }
`;

interface DraftEditionProps {
  draftId: string;
  overviewData: DraftRootFragment$data;
}

const DraftEdition: FunctionComponent<DraftEditionProps> = ({
  draftId,
  overviewData,
}) => {
  const { t_i18n } = useFormatter();
  const [commit] = useApiMutation<DraftEditionFocusMutation>(
    draftEditionFocus,
  );

  const handleClose = () => {
    commit({
      variables: {
        id: draftId,
        input: { focusOn: '' },
      },
    });
  };

  return (
    <Drawer
      title={t_i18n('Update a Draft')}
      onClose={handleClose}
      controlledDial={EditEntityControlledDial}
    >
      <DraftEditionOverview draft={overviewData} />
    </Drawer>
  );
};

export default DraftEdition;
