import React, { FunctionComponent } from 'react';
import FintelDesignEditionOverview from '@components/settings/fintel_design/FintelDesignEditionOverview';
import Drawer from '@components/common/drawer/Drawer';
import { graphql } from 'react-relay';
import { FintelDesignEditionFocusMutation } from '@components/settings/fintel_design/__generated__/FintelDesignEditionFocusMutation.graphql';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { useFormatter } from '../../../../components/i18n';
import { FintelDesignEditionOverview_fintelDesign$key } from './__generated__/FintelDesignEditionOverview_fintelDesign.graphql';
import EditEntityControlledDial from '../../../../components/EditEntityControlledDial';

const fintelDesignEditionFocus = graphql`
  mutation FintelDesignEditionFocusMutation($id: ID! $input: EditContext!) {
    fintelDesignContextPatch(id: $id, input: $input) {
      id
    }
  }
`;

interface FintelDesignEditionProps {
  fintelDesignId: string;
  overviewData: FintelDesignEditionOverview_fintelDesign$key;
}

const FintelDesignEdition: FunctionComponent<FintelDesignEditionProps> = ({
  overviewData,
  fintelDesignId,
}) => {
  const { t_i18n } = useFormatter();
  const [commit] = useApiMutation<FintelDesignEditionFocusMutation>(
    fintelDesignEditionFocus,
  );

  const handleClose = () => {
    commit({
      variables: {
        id: fintelDesignId,
        input: { focusOn: '' },
      },
    });
  };

  return (
    <Drawer
      title={t_i18n('Update a Fintel design')}
      onClose={handleClose}
      controlledDial={EditEntityControlledDial}
    >
      <FintelDesignEditionOverview data={overviewData}/>
    </Drawer>
  );
};

export default FintelDesignEdition;
