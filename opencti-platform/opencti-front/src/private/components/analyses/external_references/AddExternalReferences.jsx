import React, { useState } from 'react';
import IconButton from '@mui/material/IconButton';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { Add } from '@mui/icons-material';
import Skeleton from '@mui/material/Skeleton';
import makeStyles from '@mui/styles/makeStyles';
import { Button, styled } from '@mui/material';
import { useFormatter } from '../../../../components/i18n';
import useHelper from '../../../../utils/hooks/useHelper';
import Drawer from '../../common/drawer/Drawer';
import SearchInput from '../../../../components/SearchInput';
import { QueryRenderer } from '../../../../relay/environment';
import AddExternalReferencesLines, { addExternalReferencesLinesQuery } from './AddExternalReferencesLines';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles({
  createButton: {
    float: 'left',
    marginTop: -15,
  },
  container: {
    padding: 0,
  },
});

const StyledSearchHeader = styled('div')({
  marginLeft: 'auto',
  marginRight: '20px',
  display: 'flex',
  flexDirection: 'column',
  alignItems: 'flex-end',
});

const CreateButtonWithMargin = styled(Button)({
  marginTop: '5px',
});

const AddExternalReferences = ({
  stixCoreObjectOrStixCoreRelationshipId,
  stixCoreObjectOrStixCoreRelationshipReferences,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const [open, setOpen] = useState(false);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [search, setSearch] = useState('');
  const FABReplaced = isFeatureEnable('FAB_REPLACEMENT');

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

  const paginationOptions = { search };
  return (
    <div>
      <IconButton
        color="primary"
        aria-label="Add"
        onClick={handleOpen}
        classes={{ root: classes.createButton }}
        size="large"
      >
        <Add fontSize="small" />
      </IconButton>
      <Drawer
        title={t_i18n('Add external references')}
        open={open}
        onClose={handleClose}
        header={(
          <StyledSearchHeader>
            <SearchInput
              variant="inDrawer"
              onSubmit={handleSearch}
            />
            {FABReplaced
              && <CreateButtonWithMargin
                onClick={() => setDialogOpen(true)}
                color='primary'
                size='small'
                variant='contained'
                 >
                {t_i18n('Create')} {t_i18n('entity_External-Reference')} <Add />
              </CreateButtonWithMargin>
            }
          </StyledSearchHeader>
        )}
      >
        <div className={classes.container}>
          <QueryRenderer
            query={addExternalReferencesLinesQuery}
            variables={{
              search,
              count: 20,
            }}
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
                    open={FABReplaced ? false : open}
                    openContextual={dialogOpen}
                    handleCloseContextual={FABReplaced ? () => setDialogOpen(false) : undefined}
                    search={search}
                  />
                );
              }
              return (
                <List>
                  {Array.from(Array(20), (e, i) => (
                    <ListItem key={i} divider={true} button={false}>
                      <ListItemIcon>
                        <Skeleton
                          animation="wave"
                          variant="circular"
                          width={30}
                          height={30}
                        />
                      </ListItemIcon>
                      <ListItemText
                        primary={
                          <Skeleton
                            animation="wave"
                            variant="rectangular"
                            width="90%"
                            height={15}
                            style={{ marginBottom: 10 }}
                          />
                        }
                        secondary={
                          <Skeleton
                            animation="wave"
                            variant="rectangular"
                            width="90%"
                            height={15}
                          />
                        }
                      />
                    </ListItem>
                  ))}
                </List>
              );
            }}
          />
        </div>
      </Drawer>
    </div>
  );
};

export default AddExternalReferences;
