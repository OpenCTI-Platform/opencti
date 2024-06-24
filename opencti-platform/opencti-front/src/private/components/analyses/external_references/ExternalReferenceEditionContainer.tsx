import React, { FunctionComponent } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import Drawer, { DrawerControlledDialType, DrawerVariant } from '@components/common/drawer/Drawer';
import useHelper from 'src/utils/hooks/useHelper';
import { useFormatter } from '../../../../components/i18n';
import { ExternalReferenceEditionContainer_externalReference$data } from './__generated__/ExternalReferenceEditionContainer_externalReference.graphql';
import ExternalReferenceEditionOverview from './ExternalReferenceEditionOverview';

interface ExternalReferenceEditionContainerProps {
  handleClose: () => void
  externalReference: ExternalReferenceEditionContainer_externalReference$data
  open?: boolean
  controlledDial?: DrawerControlledDialType
}

const ExternalReferenceEditionContainer: FunctionComponent<ExternalReferenceEditionContainerProps> = ({
  handleClose,
  externalReference,
  open,
  controlledDial,
}) => {
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');

  const { editContext } = externalReference;

  return (
    <Drawer
      title={t_i18n('Update an external reference')}
      variant={!isFABReplaced && open == null ? DrawerVariant.update : undefined}
      context={editContext}
      onClose={handleClose}
      open={open}
      controlledDial={isFABReplaced ? controlledDial : undefined}
    >
      <ExternalReferenceEditionOverview
        externalReference={externalReference}
        context={editContext}
      />
    </Drawer>
  );
};

const ExternalReferenceEditionFragment = createFragmentContainer(
  ExternalReferenceEditionContainer,
  {
    externalReference: graphql`
      fragment ExternalReferenceEditionContainer_externalReference on ExternalReference {
        id
        ...ExternalReferenceEditionOverview_externalReference
        editContext {
          name
          focusOn
        }
      }
    `,
  },
);

export default ExternalReferenceEditionFragment;
