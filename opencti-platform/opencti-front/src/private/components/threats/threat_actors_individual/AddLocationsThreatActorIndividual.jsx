import React, { useState } from 'react';
import IconButton from '@mui/material/IconButton';
import { Add } from '@mui/icons-material';
import { usePreloadedQuery } from 'react-relay';
import Drawer from '../../common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import SearchInput from '../../../../components/SearchInput';
import AddLocationsThreatActorIndividualLines, { addLocationsThreatActorIndividualLinesQuery } from './AddLocationsThreatActorIndividualLines';
import LocationCreation from '../../common/location/LocationCreation';
import { insertNode } from '../../../../utils/store';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';

const AddLocationsThreatActorIndividualComponent = ({
  threatActorIndividual,
  threatActorIndividualLocations,
  queryRef,
  onSearch,
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState(false);

  const handleOpen = () => setOpen(true);
  const handleClose = () => setOpen(false);

  const data = usePreloadedQuery(
    addLocationsThreatActorIndividualLinesQuery,
    queryRef,
  );

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
              marginRight: '20px',
            }}
          >
            <SearchInput
              variant="inDrawer"
              onSubmit={onSearch}
            />
          </div>
          }
      >
        {queryRef && (
          <React.Suspense
            fallback={<Loader variant={LoaderVariant.inElement} />}
          >
            <AddLocationsThreatActorIndividualLines
              threatActorIndividual={threatActorIndividual}
              threatActorIndividualLocations={
                threatActorIndividualLocations
              }
              data={data}
            />
          </React.Suspense>
        )}
      </Drawer>
      <LocationCreation
        display={open}
        contextual={true}
        inputValue={paginationOptions.search}
        paginationOptions={paginationOptions}
        updater={updater}
      />
    </>
  );
};

const AddLocationsThreatActorIndividual = (props) => {
  const [paginationOptions, setPaginationOptions] = useState({ count: 50, search: '', types: ['Location'] });

  const queryRef = useQueryLoading(
    addLocationsThreatActorIndividualLinesQuery,
    paginationOptions,
  );
  return queryRef ? (
    <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <AddLocationsThreatActorIndividualComponent
        {...props}
        queryRef={queryRef}
        onSearch={(search) => setPaginationOptions({ count: 50, search, types: ['Location'] })}
        paginationOptions={paginationOptions}
      />
    </React.Suspense>
  ) : (
    <Loader variant={LoaderVariant.inElement} />
  );
};

export default AddLocationsThreatActorIndividual;
