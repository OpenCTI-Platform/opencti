import React from 'react';
import { graphql } from 'react-relay';
import { Button } from '@mui/material';
import NoteEditionContainer from './NoteEditionContainer';
import { QueryRenderer } from '../../../../relay/environment';
import { noteEditionOverviewFocus } from './NoteEditionOverview';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import { NoteEditionContainerQuery$data } from './__generated__/NoteEditionContainerQuery.graphql';
import { CollaborativeSecurity } from '../../../../utils/Security';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { useFormatter } from '../../../../components/i18n';

export const noteEditionQuery = graphql`
  query NoteEditionContainerQuery($id: String!) {
    note(id: $id) {
      createdBy {
        id
      }
      ...NoteEditionContainer_note
    }
  }
`;

const NoteEdition = ({ noteId }: { noteId: string }) => {
  const [commit] = useApiMutation(noteEditionOverviewFocus);

  const handleClose = () => {
    commit({
      variables: {
        id: noteId,
        input: { focusOn: '' },
      },
    });
  };

  // Can't use EditEntityControlledDial because it's too small for some reason.
  const ControlledDial = ({ onOpen }: { onOpen: () => void }) => {
    const { t_i18n } = useFormatter();
    const buttonLabel = t_i18n('Update');
    return (
      <Button
        onClick={onOpen}
        variant={'contained'}
        size='medium' // Medium size matches other buttons
        aria-label={buttonLabel}
        style={{ marginLeft: '3px' }}
      >
        {buttonLabel}
      </Button>
    );
  };

  return (
    <div>
      <QueryRenderer
        query={noteEditionQuery}
        variables={{ id: noteId }}
        render={({ props }: { props: NoteEditionContainerQuery$data }) => {
          if (props && props.note) {
            return (
              <CollaborativeSecurity
                data={props.note}
                needs={[KNOWLEDGE_KNUPDATE]}
              >
                <NoteEditionContainer
                  note={props.note}
                  handleClose={handleClose}
                  controlledDial={ControlledDial}
                />
              </CollaborativeSecurity>
            );
          }
          return <Loader variant={LoaderVariant.inElement} />;
        }}
      />
    </div>
  );
};

export default NoteEdition;
