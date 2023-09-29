import React, { FunctionComponent } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import Drawer, { DrawerVariant } from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import NoteEditionOverview from './NoteEditionOverview';
import { NoteEditionContainer_note$data } from './__generated__/NoteEditionContainer_note.graphql';

interface NoteEditionContainerProps {
  note: NoteEditionContainer_note$data
  handleClose: () => void
  open?: boolean
}

const NoteEditionContainer: FunctionComponent<NoteEditionContainerProps> = ({
  note,
  handleClose,
  open,
}) => {
  const { t } = useFormatter();

  const { editContext } = note;

  return (
    <Drawer
      title={t('Update a note')}
      variant={open == null ? DrawerVariant.update : undefined}
      context={editContext}
      onClose={handleClose}
      open={open}
    >
      {({ onClose }) => (
        <NoteEditionOverview
          note={note}
          context={editContext}
          handleClose={onClose}
        />
      )}
    </Drawer>
  );
};

const NoteEditionContainerFragment = createFragmentContainer(
  NoteEditionContainer,
  {
    note: graphql`
      fragment NoteEditionContainer_note on Note {
        ...NoteEditionOverview_note
        editContext {
          name
          focusOn
        }
      }
    `,
  },
);

export default NoteEditionContainerFragment;
