import React, { FunctionComponent, useState } from 'react';
import { ThreatActorIndividual_ThreatActorIndividual$data } from '@components/threats/threat_actors_individual/__generated__/ThreatActorIndividual_ThreatActorIndividual.graphql';
import IconButton from '@mui/material/IconButton';
import { Add } from '@mui/icons-material';
import Drawer from '@components/common/drawer/Drawer';
import CountryCreation from '@components/locations/countries/CountryCreation';
import AddThreatActorIndividualDemographicLines, {
  addIndividualsThreatActorIndividualLinesQuery,
} from '@components/threats/threat_actors_individual/AddThreatActorIndividualDemographicLines';
import { AddThreatActorIndividualDemographicLinesQuery } from '@components/threats/threat_actors_individual/__generated__/AddThreatActorIndividualDemographicLinesQuery.graphql';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import SearchInput from '../../../../components/SearchInput';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';

interface AddThreatActorIndividualDemographicProps {
  threatActorIndividual: ThreatActorIndividual_ThreatActorIndividual$data,
  relType: string,
  title:string,
  queryRef: PreloadedQuery<AddThreatActorIndividualDemographicLinesQuery>;
}

const AddThreatActorIndividualDemographicComponent: FunctionComponent<
AddThreatActorIndividualDemographicProps
> = ({
  threatActorIndividual,
  relType,
  title,
  queryRef,
}) => {
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState<boolean>(false);
  const [search, setSearch] = useState<string>('');

  const handleOpen = () => setOpen(true);
  const handleClose = () => setOpen(false);
  const handleSearch = (term: string) => setSearch(term);

  const data = usePreloadedQuery<AddThreatActorIndividualDemographicLinesQuery>(
    addIndividualsThreatActorIndividualLinesQuery,
    queryRef,
  );

  return (<div>
    <IconButton
      color='primary'
      style={{ marginTop: '-11px' }}
      onClick={handleOpen}
    >
      <Add fontSize="small" />
    </IconButton>
    <Drawer
      open={open}
      onClose={handleClose}
      title={t_i18n(title)}
      header={
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
            variant='inDrawer'
            onSubmit={handleSearch}
          />
          <CountryCreation
            paginationOptions={{
              search,
              count: 50,
            }}
          />
        </div>
      }
    >
      <AddThreatActorIndividualDemographicLines
        threatActorIndividual={threatActorIndividual}
        fragmentKey={data}
        relType={relType}
      />
    </Drawer>
  </div>);
};

const AddThreatActorIndividualDemographic: FunctionComponent<
Omit<AddThreatActorIndividualDemographicProps, 'queryRef'>
> = (props) => {
  const queryRef = useQueryLoading<AddThreatActorIndividualDemographicLinesQuery>(addIndividualsThreatActorIndividualLinesQuery, {
    count: 50,
  });
  return queryRef ? (
    <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <AddThreatActorIndividualDemographicComponent {...props} queryRef={queryRef} />
    </React.Suspense>
  ) : (
    <Loader variant={LoaderVariant.inElement} />
  );
};

export default AddThreatActorIndividualDemographic;
