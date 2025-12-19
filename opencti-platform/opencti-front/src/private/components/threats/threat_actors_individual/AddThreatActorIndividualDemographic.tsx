import React, { FunctionComponent, useState } from 'react';
import { ThreatActorIndividual_ThreatActorIndividual$data } from '@components/threats/threat_actors_individual/__generated__/ThreatActorIndividual_ThreatActorIndividual.graphql';
import IconButton from '@common/button/IconButton';
import { Add } from '@mui/icons-material';
import Drawer from '@components/common/drawer/Drawer';
import CountryCreation from '@components/locations/countries/CountryCreation';
import AddThreatActorIndividualDemographicLines, {
  addIndividualsThreatActorIndividualLinesQuery,
} from '@components/threats/threat_actors_individual/AddThreatActorIndividualDemographicLines';
import {
  AddThreatActorIndividualDemographicLinesQuery,
  AddThreatActorIndividualDemographicLinesQuery$variables,
} from '@components/threats/threat_actors_individual/__generated__/AddThreatActorIndividualDemographicLinesQuery.graphql';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import SearchInput from '../../../../components/SearchInput';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';

interface AddThreatActorIndividualDemographicComponentProps {
  threatActorIndividual: ThreatActorIndividual_ThreatActorIndividual$data;
  relType: string;
  title: string;
  queryRef: PreloadedQuery<AddThreatActorIndividualDemographicLinesQuery>;
  onSearch: (search: string) => void;
  paginationOptions: AddThreatActorIndividualDemographicLinesQuery$variables;
}

const AddThreatActorIndividualDemographicComponent: FunctionComponent<
  AddThreatActorIndividualDemographicComponentProps
> = ({
  threatActorIndividual,
  relType,
  title,
  queryRef,
  onSearch,
  paginationOptions,
}) => {
  const [open, setOpen] = useState<boolean>(false);

  const handleOpen = () => setOpen(true);
  const handleClose = () => setOpen(false);

  const data = usePreloadedQuery<AddThreatActorIndividualDemographicLinesQuery>(
    addIndividualsThreatActorIndividualLinesQuery,
    queryRef,
  );

  return (
    <div>
      <IconButton
        color="primary"
        onClick={handleOpen}
      >
        <Add fontSize="small" />
      </IconButton>
      <Drawer
        open={open}
        onClose={handleClose}
        title={title}
        header={(
          <div
            style={{
              marginLeft: 'auto',
              marginRight: '20px',
              display: 'flex',
              flexWrap: 'wrap',
              justifyContent: 'flex-end',
              alignItems: 'flex-end',
            }}
          >
            <SearchInput
              variant="inDrawer"
              onSubmit={onSearch}
            />
            <CountryCreation
              paginationOptions={paginationOptions}
            />
          </div>
        )}
      >
        <AddThreatActorIndividualDemographicLines
          threatActorIndividual={threatActorIndividual}
          fragmentKey={data}
          relType={relType}
        />
      </Drawer>
    </div>
  );
};

interface AddThreatActorIndividualDemographicProps {
  threatActorIndividual: ThreatActorIndividual_ThreatActorIndividual$data;
  relType: string;
  title: string;
}

const AddThreatActorIndividualDemographic: FunctionComponent<AddThreatActorIndividualDemographicProps> = (props) => {
  const [paginationOptions, setPaginationOptions] = useState({ count: 50, search: '' });
  const queryRef = useQueryLoading<AddThreatActorIndividualDemographicLinesQuery>(
    addIndividualsThreatActorIndividualLinesQuery,
    paginationOptions,
  );
  return queryRef ? (
    <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <AddThreatActorIndividualDemographicComponent
        {...props}
        queryRef={queryRef}
        onSearch={(search) => setPaginationOptions({ count: 50, search })}
        paginationOptions={paginationOptions}
      />
    </React.Suspense>
  ) : (
    <Loader variant={LoaderVariant.inElement} />
  );
};

export default AddThreatActorIndividualDemographic;
