import React, { FunctionComponent } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import Drawer, { DrawerVariant } from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import { ExternalReferenceEditionContainer_externalReference$data } from './__generated__/ExternalReferenceEditionContainer_externalReference.graphql';
import ExternalReferenceEditionOverview from './ExternalReferenceEditionOverview';

interface ExternalReferenceEditionContainerProps {
  handleClose: () => void
  externalReference: ExternalReferenceEditionContainer_externalReference$data
  controlledDial?: (({ onOpen, onClose }: {
    onOpen: () => void;
    onClose: () => void;
  }) => React.ReactElement<unknown, string | React.JSXElementConstructor<unknown>>)
  open?: boolean
}

const ExternalReferenceEditionContainer: FunctionComponent<ExternalReferenceEditionContainerProps> = ({
  handleClose,
  externalReference,
  controlledDial,
  open,
}) => {
  const { t_i18n } = useFormatter();

  const { editContext } = externalReference;

  return (
    <Drawer
      title={t_i18n('Update an external reference')}
      variant={open == null && controlledDial === null
        ? DrawerVariant.update
        : undefined}
      context={editContext}
      onClose={handleClose}
      open={open}
      controlledDial={controlledDial}
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
