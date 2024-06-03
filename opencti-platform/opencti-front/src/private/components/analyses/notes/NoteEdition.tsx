import React from 'react';
import { graphql } from 'react-relay';
import NoteEditionContainer from './NoteEditionContainer';
import { QueryRenderer } from '../../../../relay/environment';
import { noteEditionOverviewFocus } from './NoteEditionOverview';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import { NoteEditionContainerQuery$data } from './__generated__/NoteEditionContainerQuery.graphql';
import { CollaborativeSecurity } from '../../../../utils/Security';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import EditEntityControlledDial from '../../../../components/EditEntityControlledDial';

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

  return (
    <QueryRenderer
      query={noteEditionQuery}
      variables={{ id: noteId }}
      render={({ props }: { props: NoteEditionContainerQuery$data }) => {
        if (props?.note) {
          return (
            <CollaborativeSecurity
              data={props.note}
              needs={[KNOWLEDGE_KNUPDATE]}
            >
              <NoteEditionContainer
                note={props.note}
                handleClose={handleClose}
                controlledDial={EditEntityControlledDial}
              />
            </CollaborativeSecurity>
          );
        }
        return <Loader variant={LoaderVariant.inline} />;
      }}
    />
  );
};

export default NoteEdition;
