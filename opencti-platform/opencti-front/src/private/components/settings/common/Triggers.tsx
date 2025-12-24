import Grid from '@mui/material/Grid';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@mui/material/IconButton';
import { BackupTableOutlined, CampaignOutlined } from '@mui/icons-material';
import React, { FunctionComponent, useRef, useState } from 'react';
import { Stack } from '@mui/material';
import TriggerLiveCreation from '../../profile/triggers/TriggerLiveCreation';
import ColumnsLinesTitles from '../../../../components/ColumnsLinesTitles';
import TriggersLines, { triggersLinesQuery } from '../../profile/triggers/TriggersLines';
import TriggerDigestCreation from '../../profile/triggers/TriggerDigestCreation';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { useFormatter } from '../../../../components/i18n';
import { TriggersLinesPaginationQuery, TriggersLinesPaginationQuery$variables } from '../../profile/triggers/__generated__/TriggersLinesPaginationQuery.graphql';
import SearchInput from '../../../../components/SearchInput';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { LOCAL_STORAGE_KEY_TRIGGERS } from '../../profile/Triggers';
import { TriggerLineDummy } from '../../profile/triggers/TriggerLine';
import { GqlFilterGroup, emptyFilterGroup } from '../../../../utils/filters/filtersUtils';
import Card from '../../../../components/common/card/Card';

interface TriggersProps {
  recipientId: string;
  filterKey: string;
}
const Triggers: FunctionComponent<TriggersProps> = ({
  recipientId,
  filterKey,
}) => {
  const { t_i18n } = useFormatter();
  const ref = useRef(null);
  const {
    viewStorage,
    helpers,
    paginationOptions: paginationOptionsFromStorage,
  } = usePaginationLocalStorage<TriggersLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY_TRIGGERS,
    {
      searchTerm: '',
      sortBy: 'name',
      orderAsc: true,
      filters: emptyFilterGroup,
      numberOfElements: {
        number: 0,
        symbol: '',
      },
    },
    true,
  );
  const { searchTerm, sortBy, orderAsc } = viewStorage;

  const paginationOptions = {
    ...paginationOptionsFromStorage,
    count: 25,
    includeAuthorities: true,
    filters: {
      mode: 'and',
      filters: [
        { key: [filterKey], values: [recipientId], operator: 'eq', mode: 'or' },
      ],
      filterGroups: [],
    } as GqlFilterGroup,
  };
  const queryRef = useQueryLoading<TriggersLinesPaginationQuery>(
    triggersLinesQuery,
    paginationOptions,
  );
  const dataColumns = {
    trigger_type: {
      label: 'Type',
      width: '10%',
      isSortable: true,
    },
    name: {
      label: 'Name',
      width: '15%',
      isSortable: true,
    },
    notifiers: {
      label: 'Notification',
      width: '20%',
      isSortable: true,
    },
    event_types: {
      label: 'Triggering on',
      width: '20%',
      isSortable: false,
    },
    filters: {
      label: 'Details',
      width: '35%',
      isSortable: false,
    },
  };
  const [openLive, setOpenLive] = useState(false);
  const [openDigest, setOpenDigest] = useState(false);
  return (
    <Grid item xs={12} style={{ marginTop: 10 }}>
      <Card
        title={t_i18n('Triggers and Digests')}
        action={(
          <Stack direction="row" gap={1}>
            <div>
              <Tooltip title={t_i18n('Add a live trigger')}>
                <IconButton
                  aria-label="Add"
                  onClick={() => setOpenLive(true)}
                  size="small"
                  color="primary"
                >
                  <CampaignOutlined fontSize="small" />
                </IconButton>
              </Tooltip>
              <TriggerLiveCreation
                paginationOptions={paginationOptions}
                open={openLive}
                handleClose={() => setOpenLive(false)}
                recipientId={recipientId}
              />
              <Tooltip title={t_i18n('Add a regular digest')}>
                <IconButton
                  aria-label="Add"
                  onClick={() => setOpenDigest(true)}
                  size="small"
                  color="primary"
                >
                  <BackupTableOutlined fontSize="small" />
                </IconButton>
              </Tooltip>
            </div>
            <SearchInput
              style={{ transform: 'translateY(-5px)' }}
              variant="thin"
              onSubmit={helpers.handleSearch}
              keyword={searchTerm}
            />
          </Stack>
        )}
      >
        <div ref={ref}>
          <ColumnsLinesTitles
            dataColumns={dataColumns}
            sortBy={sortBy}
            orderAsc={orderAsc}
            handleSort={helpers.handleSort}
            secondaryAction={true}
          />
          {queryRef && (
            <React.Suspense
              fallback={(
                <>
                  {Array(20)
                    .fill(0)
                    .map((_, idx) => (
                      <TriggerLineDummy key={idx} dataColumns={dataColumns} />
                    ))}
                </>
              )}
            >
              <TriggersLines
                queryRef={queryRef}
                containerRef={ref}
                paginationOptions={paginationOptions}
                dataColumns={dataColumns}
                bypassEditionRestriction={true}
              />
            </React.Suspense>
          )}
        </div>
      </Card>
      <TriggerDigestCreation
        paginationOptions={paginationOptions}
        open={openDigest}
        handleClose={() => setOpenDigest(false)}
        recipientId={recipientId}
      />
    </Grid>
  );
};

export default Triggers;
