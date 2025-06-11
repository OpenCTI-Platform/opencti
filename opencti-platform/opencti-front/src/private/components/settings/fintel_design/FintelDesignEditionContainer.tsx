import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Drawer, { DrawerControlledDialType } from '@components/common/drawer/Drawer';
import FintelDesignEditionOverview from '@components/settings/fintel_design/FintelDesignEditionOverview';
import { useFormatter } from '../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { FintelDesignEditionContainerQuery } from './__generated__/FintelDesignEditionContainerQuery.graphql';

interface FintelDesignEditionContainerProps {
  handleClose: () => void
  queryRef: PreloadedQuery<FintelDesignEditionContainerQuery>
  open?: boolean
  controlledDial?: DrawerControlledDialType
}

export const fintelDesignEditionQuery = graphql`
  query FintelDesignEditionContainerQuery($id: String!) {
    fintelDesign(id: $id) {
      ...FintelDesignEditionOverview_fintelDesign
    }
  }
`;

const FintelDesignEditionContainer: FunctionComponent<FintelDesignEditionContainerProps> = ({
  handleClose,
  queryRef,
  open,
  controlledDial,
}) => {
  const { t_i18n } = useFormatter();
  const { fintelDesign } = usePreloadedQuery(fintelDesignEditionQuery, queryRef);
  if (!fintelDesign) {
    return <Loader variant={LoaderVariant.inline} />;
  }
  return (
    <Drawer
      title={t_i18n('Update a Fintel design')}
      onClose={handleClose}
      open={open}
      controlledDial={controlledDial}
    >
      {() => (
        <FintelDesignEditionOverview
          fintelDesignRef={fintelDesign}
        />
      )}
    </Drawer>
  );
};

export default FintelDesignEditionContainer;
