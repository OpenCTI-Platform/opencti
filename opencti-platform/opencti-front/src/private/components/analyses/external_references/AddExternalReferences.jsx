import React, { useState } from 'react';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { Add } from '@mui/icons-material';
import Skeleton from '@mui/material/Skeleton';
import { useFormatter } from '../../../../components/i18n';
import Drawer from '../../common/drawer/Drawer';
import SearchInput from '../../../../components/SearchInput';
import { QueryRenderer } from '../../../../relay/environment';
import AddExternalReferencesLines, { addExternalReferencesLinesQuery } from './AddExternalReferencesLines';

const AddExternalReferences = ({
  stixCoreObjectOrStixCoreRelationshipId,
  stixCoreObjectOrStixCoreRelationshipReferences,
}) => {
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState(false);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [search, setSearch] = useState('');

  const handleOpen = () => {
    setOpen(true);
  };

  const handleClose = () => {
    setOpen(false);
    setSearch('');
  };

  const handleSearch = (keyword) => {
    setSearch(keyword);
  };

  const paginationOptions = {
    search,
    orderBy: 'created_at',
    orderMode: 'desc',
    count: 20,
  };
  return (
    <>
      <IconButton
        variant="tertiary"
        size="small"
        aria-label="Add"
        onClick={handleOpen}
        style={{
          float: 'left',
          marginLeft: 4,
          marginTop: -6,
          marginBottom: 10,
        }}
      >
        <Add />
      </IconButton>
      <Drawer
        title={t_i18n('Add external references')}
        open={open}
        onClose={handleClose}
        header={(
          <div style={{
            marginLeft: 'auto',
            marginRight: '20px',
            display: 'flex',
            flexWrap: 'wrap',
            alignItems: 'flex-end',
            justifyContent: 'flex-end',
          }}
          >
            <SearchInput
              variant="inDrawer"
              onSubmit={handleSearch}
            />
            <Button
              sx={{ margin: '5px 0 0 5px' }}
              onClick={() => setDialogOpen(true)}
              size="small"
            >
              {t_i18n('Create')} {t_i18n('entity_External-Reference')}
            </Button>
          </div>
        )}
      >
        <div style={{ padding: 0 }}>
          <QueryRenderer
            query={addExternalReferencesLinesQuery}
            variables={paginationOptions}
            render={({ props }) => {
              if (props) {
                return (
                  <AddExternalReferencesLines
                    stixCoreObjectOrStixCoreRelationshipId={
                      stixCoreObjectOrStixCoreRelationshipId
                    }
                    stixCoreObjectOrStixCoreRelationshipReferences={
                      stixCoreObjectOrStixCoreRelationshipReferences
                    }
                    data={props}
                    paginationOptions={paginationOptions}
                    open={false}
                    openContextual={dialogOpen}
                    handleCloseContextual={() => setDialogOpen(false)}
                    search={search}
                  />
                );
              }
              return (
                <List>
                  {Array.from(Array(20), (e, i) => (
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
        </div>
      </Drawer>
    </>
  );
};

export default AddExternalReferences;
