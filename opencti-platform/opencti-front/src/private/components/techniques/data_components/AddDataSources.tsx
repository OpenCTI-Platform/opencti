import React, { FunctionComponent, useState } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import IconButton from '@mui/material/IconButton';
import { Add } from '@mui/icons-material';
import Drawer from '@components/common/drawer/Drawer';
import { DataSourcesLinesPaginationQuery$variables } from '@components/techniques/__generated__/DataSourcesLinesPaginationQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import DataSourceCreation from '../data_sources/DataSourceCreation';
import SearchInput from '../../../../components/SearchInput';
import AddDataSourcesLines, { addDataSourcesLinesQuery } from './AddDataSourcesLines';
import { AddDataSourcesLinesQuery } from './__generated__/AddDataSourcesLinesQuery.graphql';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  createButton: {
    float: 'left',
    marginTop: -15,
  },
}));

const AddDataSources: FunctionComponent<{ dataComponentId: string }> = ({
  dataComponentId,
}) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();

  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState('');
  const paginationOptions: DataSourcesLinesPaginationQuery$variables = {
    search,
    count: 20,
  };

  const handleSearch = (keyword: string) => setSearch(keyword);
  const handleOpen = () => setOpen(true);
  const handleClose = () => {
    setOpen(false);
    setSearch('');
  };

  const queryRef = useQueryLoading<AddDataSourcesLinesQuery>(
    addDataSourcesLinesQuery,
    { ...paginationOptions },
  );

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
        open={open}
        onClose={handleClose}
        title={t_i18n('Add data sources')}
        header={(
          <div style={{
            marginLeft: 'auto',
            marginRight: '20px',
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'flex-end',
          }}
          >
            <SearchInput
              variant="inDrawer"
              onSubmit={handleSearch}
            />
            <DataSourceCreation
              contextual={true}
              display={open}
              inputValue={search}
              paginationOptions={paginationOptions}
            />
          </div>
        )}
      >
        {queryRef && (
          <React.Suspense
            fallback={<Loader variant={LoaderVariant.inElement} />}
          >
            <AddDataSourcesLines
              dataComponentId={dataComponentId}
              queryRef={queryRef}
            />
          </React.Suspense>
        )}
      </Drawer>
    </div>
  );
};

export default AddDataSources;
