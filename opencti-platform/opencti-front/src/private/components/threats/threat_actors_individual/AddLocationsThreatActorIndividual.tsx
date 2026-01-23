import React, { FunctionComponent, useState } from 'react';
import IconButton from '@common/button/IconButton';
import { Add } from '@mui/icons-material';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import {
  AddLocationsThreatActorIndividualLinesQuery,
  AddLocationsThreatActorIndividualLinesQuery$variables,
} from '@components/threats/threat_actors_individual/__generated__/AddLocationsThreatActorIndividualLinesQuery.graphql';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { ThreatActorIndividualLocations_locations$data } from '@components/threats/threat_actors_individual/__generated__/ThreatActorIndividualLocations_locations.graphql';
import Drawer from '../../common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import SearchInput from '../../../../components/SearchInput';
import AddLocationsThreatActorIndividualLines, { addLocationsThreatActorIndividualLinesQuery } from './AddLocationsThreatActorIndividualLines';
import LocationCreation from '../../common/location/LocationCreation';
import { insertNode } from '../../../../utils/store';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { Stack } from '@mui/material';

interface AddLocationsThreatActorIndividualComponentProps {
  threatActorIndividual: ThreatActorIndividualLocations_locations$data;
  queryRef: PreloadedQuery<AddLocationsThreatActorIndividualLinesQuery>;
  onSearch: (search: string) => void;
  paginationOptions: AddLocationsThreatActorIndividualLinesQuery$variables;
}

const AddLocationsThreatActorIndividualComponent: FunctionComponent<AddLocationsThreatActorIndividualComponentProps> = ({
  threatActorIndividual,
  queryRef,
  onSearch,
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState(false);

  const handleOpen = () => setOpen(true);
  const handleClose = () => setOpen(false);

  const threatActorIndividualLocations = threatActorIndividual.locations?.edges;
  const data = usePreloadedQuery(
    addLocationsThreatActorIndividualLinesQuery,
    queryRef,
  );

  const updater = (store: RecordSourceSelectorProxy) => insertNode(
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

      >
        <Add fontSize="small" />
      </IconButton>
      <Drawer
        open={open}
        onClose={handleClose}
        title={t_i18n('Add locations')}
      >
        {queryRef && (
          <React.Suspense
            fallback={<Loader variant={LoaderVariant.inElement} />}
          >
            <Stack gap={2}>
              <Stack gap={1} direction="row" justifyContent="space-between">
                <SearchInput
                  variant="inDrawer"
                  onSubmit={onSearch}
                />
                <LocationCreation
                  display={open}
                  contextual={true}
                  inputValue={paginationOptions.search ?? ''}
                  updater={updater}
                />
              </Stack>
              <AddLocationsThreatActorIndividualLines
                threatActorIndividual={threatActorIndividual}
                threatActorIndividualLocations={
                  threatActorIndividualLocations
                }
                data={data}
              />
            </Stack>
          </React.Suspense>
        )}
      </Drawer>
    </>
  );
};

interface AddLocationsThreatActorIndividualProps {
  threatActorIndividual: ThreatActorIndividualLocations_locations$data;
}
const AddLocationsThreatActorIndividual: FunctionComponent<AddLocationsThreatActorIndividualProps> = ({
  threatActorIndividual,
}) => {
  const [paginationOptions, setPaginationOptions] = useState({ count: 50, search: '', types: ['Location'] });

  const queryRef = useQueryLoading<AddLocationsThreatActorIndividualLinesQuery>(
    addLocationsThreatActorIndividualLinesQuery,
    paginationOptions,
  );
  return queryRef ? (
    <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <AddLocationsThreatActorIndividualComponent
        threatActorIndividual={threatActorIndividual}
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
