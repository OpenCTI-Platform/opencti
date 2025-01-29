import React, { useState } from 'react';
import IconButton from '@mui/material/IconButton';
import { Add } from '@mui/icons-material';
import Drawer from '../../common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import SearchInput from '../../../../components/SearchInput';
import { QueryRenderer } from '../../../../relay/environment';
import AddLocationsThreatActorIndividualLines, { addLocationsThreatActorIndividualLinesQuery } from './AddLocationsThreatActorIndividualLines';
import LocationCreation from '../../common/location/LocationCreation';
import { insertNode } from '../../../../utils/store';

const AddLocationsThreatActorIndividual = ({
  threatActorIndividual,
  threatActorIndividualLocations,
}) => {
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState('');

  const handleOpen = () => setOpen(true);
  const handleClose = () => setOpen(false);
  const handleSearch = (term) => setSearch(term);

  const paginationOptions = {
    search,
  };
  const updater = (store) => insertNode(
    store,
    'Pagination_threatActorIndividual_locations',
    paginationOptions,
    'locationAdd',
  );
  return (
    <>
      <IconButton
        color="primary"
        aria-label="Add"
        onClick={handleOpen}
        size="large"
        style={{
          marginTop: -15,
          float: 'left',
        }}
      >
        <Add fontSize="small" />
      </IconButton>
      <Drawer
        open={open}
        onClose={handleClose}
        title={t_i18n('Add locations')}
        header={
          <div
            style={{
              marginLeft: 'auto',
              marginRight: ' 20px',
            }}
          >
            <SearchInput
              variant="inDrawer"
              onSubmit={handleSearch}
            />
          </div>
          }
      >
        <QueryRenderer
          query={addLocationsThreatActorIndividualLinesQuery}
          variables={{
            search,
            count: 50,
          }}
          render={({ props }) => {
            return (
              <AddLocationsThreatActorIndividualLines
                threatActorIndividual={threatActorIndividual}
                threatActorIndividualLocations={
                    threatActorIndividualLocations
                  }
                data={props}
              />
            );
          }}
        />
      </Drawer>
      <LocationCreation
        display={open}
        contextual={true}
        inputValue={search}
        paginationOptions={paginationOptions}
        updater={updater}
      />
    </>
  );
};

export default AddLocationsThreatActorIndividual;
