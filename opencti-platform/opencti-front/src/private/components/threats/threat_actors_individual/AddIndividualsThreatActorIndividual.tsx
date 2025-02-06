import Drawer from '@components/common/drawer/Drawer';
import { Add } from '@mui/icons-material';
import { IconButton } from '@mui/material';
import React, { FunctionComponent, useState } from 'react';
import SearchInput from 'src/components/SearchInput';
import { useFormatter } from 'src/components/i18n';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import AddIndividualsThreatActorIndividualLines, { addIndividualsThreatActorIndividualLinesQuery } from './AddIndividualsThreatActorIndividualLines';
import {
  AddIndividualsThreatActorIndividualLinesQuery,
  AddIndividualsThreatActorIndividualLinesQuery$variables,
} from './__generated__/AddIndividualsThreatActorIndividualLinesQuery.graphql';
import { ThreatActorIndividualDetails_ThreatActorIndividual$data } from './__generated__/ThreatActorIndividualDetails_ThreatActorIndividual.graphql';
import IndividualCreation from '../../entities/individuals/IndividualCreation';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';

interface AddIndividualsThreatActorIndividualComponentProps {
  threatActorIndividual: ThreatActorIndividualDetails_ThreatActorIndividual$data,
  queryRef: PreloadedQuery<AddIndividualsThreatActorIndividualLinesQuery>,
  onSearch: (search: string) => void,
  paginationOptions: AddIndividualsThreatActorIndividualLinesQuery$variables,
}

const AddIndividualsThreatActorIndividualComponent: FunctionComponent<
AddIndividualsThreatActorIndividualComponentProps
> = ({
  threatActorIndividual,
  queryRef,
  onSearch,
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState<boolean>(false);

  const handleOpen = () => setOpen(true);
  const handleClose = () => setOpen(false);

  const data = usePreloadedQuery<AddIndividualsThreatActorIndividualLinesQuery>(
    addIndividualsThreatActorIndividualLinesQuery,
    queryRef,
  );

  return (<div>
    <IconButton
      color='primary'
      onClick={handleOpen}
    >
      <Add fontSize="small" />
    </IconButton>
    <Drawer
      open={open}
      onClose={handleClose}
      title={t_i18n('Add individual')}
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
            onSubmit={onSearch}
          />
          <div style={{ height: 5 }} />
          <IndividualCreation
            paginationOptions={paginationOptions}
          />
        </div>
      }
    >
      <AddIndividualsThreatActorIndividualLines
        threatActorIndividual={threatActorIndividual}
        fragmentKey={data}
      />
    </Drawer>
  </div>);
};

interface AddIndividualsThreatActorIndividualProps {
  threatActorIndividual: ThreatActorIndividualDetails_ThreatActorIndividual$data,
}

const AddIndividualsThreatActorIndividual: FunctionComponent<AddIndividualsThreatActorIndividualProps> = (props) => {
  const [paginationOptions, setPaginationOptions] = useState({ count: 50, search: '' });
  const queryRef = useQueryLoading<AddIndividualsThreatActorIndividualLinesQuery>(
    addIndividualsThreatActorIndividualLinesQuery,
    paginationOptions,
  );
  return queryRef ? (
    <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <AddIndividualsThreatActorIndividualComponent
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

export default AddIndividualsThreatActorIndividual;
