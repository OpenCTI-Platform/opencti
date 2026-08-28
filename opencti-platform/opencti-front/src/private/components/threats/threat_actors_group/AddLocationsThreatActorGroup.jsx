import React, { useState } from 'react';
import * as PropTypes from 'prop-types';
import withStyles from '@mui/styles/withStyles';
import IconButton from '@common/button/IconButton';
import { Add } from '@mui/icons-material';
import Drawer from '../../common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import SearchInput from '../../../../components/SearchInput';
import { QueryRenderer } from '../../../../relay/environment';
import LocationCreation from '../../common/location/LocationCreation';
import AddLocationsThreatActorGroupLines, { addLocationsThreatActorGroupLinesQuery } from './AddLocationsThreatActorGroupLines';
import { insertNode } from '../../../../utils/store';

const styles = () => ({
  search: {
    marginLeft: 'auto',
    marginRight: ' 20px',
  },
});

const AddLocationsThreatActorGroup = (props) => {
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState(false);
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

  const { threatActorGroup, threatActorGroupLocations } = props;
  const paginationOptions = {
    search: search,
  };
  const updater = (store) => insertNode(
    store,
    'Pagination_threatActorGroup_locations',
    paginationOptions,
    'locationAdd',
  );
  return (
    <>
      <IconButton
        color="primary"
        aria-label="Add"
        onClick={handleOpen}
      >
        <Add fontSize="small" />
      </IconButton>
      <Drawer
        open={open}
        onClose={handleClose}
        title={t_i18n('Add locations')}
        subHeader={{
          right: [(
            <LocationCreation
              display={open}
              contextual={true}
              inputValue={search}
              paginationOptions={paginationOptions}
              updater={updater}
              key="rightButton"
            />
          )],
          left: [(
            <SearchInput
              variant="inDrawer"
              onSubmit={handleSearch}
              key="leftInput"
            />
          )],
        }}
      >
        <QueryRenderer
          query={addLocationsThreatActorGroupLinesQuery}
          variables={{
            search: search,
            count: 100,
          }}
          render={({ props }) => {
            return (
              <AddLocationsThreatActorGroupLines
                threatActorGroup={threatActorGroup}
                threatActorGroupLocations={threatActorGroupLocations}
                data={props}
              />
            );
          }}
        />
      </Drawer>

    </>
  );
};

AddLocationsThreatActorGroup.propTypes = {
  threatActorGroup: PropTypes.object,
  threatActorGroupLocations: PropTypes.array,
  classes: PropTypes.object,
};

export default withStyles(styles)(AddLocationsThreatActorGroup);
