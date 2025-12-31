import React, { FunctionComponent, useState } from 'react';
import { Dialog, DialogContent, DialogTitle, IconButton, List, ListItem, ListItemIcon, ListItemText, Skeleton } from '@mui/material';
import Button from '@common/button/Button';
import { Add } from '@mui/icons-material';
import Drawer from '@components/common/drawer/Drawer';
import { useFormatter } from 'src/components/i18n';
import SearchInput from 'src/components/SearchInput';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { QueryRenderer } from 'src/relay/environment';
import { insertNode } from 'src/utils/store';
import { NotesLinesPaginationQuery$variables } from '@components/analyses/__generated__/NotesLinesPaginationQuery.graphql';
import AddNotesLines, { addNotesLinesQuery } from './AddNotesLines';
import { AddNotesLinesQuery$data } from './__generated__/AddNotesLinesQuery.graphql';
import { NoteCreationForm } from './NoteCreation';
import { StixCoreObjectOrStixCoreRelationshipNotesCards_data$data } from './__generated__/StixCoreObjectOrStixCoreRelationshipNotesCards_data.graphql';

interface AddNotesFunctionalComponentProps {
  stixCoreObjectOrStixCoreRelationshipId: string;
  stixCoreObjectOrStixCoreRelationshipNotes: StixCoreObjectOrStixCoreRelationshipNotesCards_data$data;
  paginationOptions: NotesLinesPaginationQuery$variables;
}

// TODO: Rename to AddNotes and replace AddNotes.jsx
const AddNotesFunctionalComponent: FunctionComponent<AddNotesFunctionalComponentProps> = ({
  stixCoreObjectOrStixCoreRelationshipId,
  stixCoreObjectOrStixCoreRelationshipNotes,
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState<boolean>(false);
  const [dialogOpen, setDialogOpen] = useState<boolean>(false);
  const [search, setSearch] = useState<string>('');
  const updater = (store: RecordSourceSelectorProxy, key: string) => {
    return insertNode(store, 'Pagination_notes', { search }, key);
  };

  const handleOpen = () => {
    setOpen(true);
  };

  const handleClose = () => {
    setOpen(false);
    setSearch('');
  };

  const handleDialogOpen = () => {
    setDialogOpen(true);
  };

  const handleDialogClose = () => {
    setDialogOpen(false);
  };

  const handleSearch = (keyword: string) => {
    setSearch(keyword);
  };

  return (
    <>
      <IconButton
        color="primary"
        aria-label={t_i18n('Add')}
        onClick={handleOpen}
        size="large"
        style={{
          float: 'right',
          marginTop: -15,
        }}
      >
        <Add
          fontSize="small"
        />
      </IconButton>
      <Drawer
        open={open}
        onClose={handleClose}
        title={t_i18n('Add notes')}
        header={(
          <div style={{
            marginLeft: 'auto',
            marginRight: '20px',
          }}
          >
            <SearchInput
              variant="noAnimation"
              onSubmit={handleSearch}
            />
            <Button
              onClick={handleDialogOpen}
              size="small"
              sx={{
                marginLeft: '10px',
                padding: '7px 10px',
              }}
            >
              {t_i18n('Create')} {t_i18n('entity_Note')}
            </Button>
          </div>
        )}
      >
        <QueryRenderer
          query={addNotesLinesQuery}
          variables={{
            search,
            count: 20,
          }}
          render={({ props }: { props: AddNotesLinesQuery$data }) => {
            if (props) {
              return (
                <AddNotesLines
                  stixCoreObjectOrStixCoreRelationshipId={
                    stixCoreObjectOrStixCoreRelationshipId
                  }
                  stixCoreObjectOrStixCoreRelationshipNotes={
                    stixCoreObjectOrStixCoreRelationshipNotes.notes?.edges ?? []
                  }
                  data={props}
                  paginationOptions={paginationOptions}
                />
              );
            }
            return (
              <List>
                {Array.from(Array(20), (_, i) => (
                  <ListItem key={i} divider={true}>
                    <ListItemIcon>
                      <Skeleton
                        animation="wave"
                        variant="circular"
                        width={30}
                        height={30}
                      />
                    </ListItemIcon>
                    <ListItemText
                      primary={(
                        <Skeleton
                          animation="wave"
                          variant="rectangular"
                          width="90%"
                          height={15}
                          style={{ marginBottom: 10 }}
                        />
                      )}
                      secondary={(
                        <Skeleton
                          animation="wave"
                          variant="rectangular"
                          width="90%"
                          height={15}
                        />
                      )}
                    />
                  </ListItem>
                ))}
              </List>
            );
          }}
        />
      </Drawer>
      <Dialog
        open={dialogOpen}
        onClose={handleDialogClose}
        slotProps={{
          paper: {
            elevation: 1,
            style: { width: 800 },
          },
        }}
      >
        <DialogTitle>{t_i18n('Create a note')}</DialogTitle>
        <DialogContent>
          <NoteCreationForm
            inputValue={search}
            updater={updater}
            onClose={handleDialogClose}
          />
        </DialogContent>
      </Dialog>
    </>
  );
};

export default AddNotesFunctionalComponent;
