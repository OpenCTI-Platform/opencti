import React, { FunctionComponent, useState } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import IconButton from '@mui/material/IconButton';
import { Add } from '@mui/icons-material';
import Drawer from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import DataSourceCreation from '../data_sources/DataSourceCreation';
import SearchInput from '../../../../components/SearchInput';
import AddDataSourcesLines, { addDataSourcesLinesQuery } from './AddDataSourcesLines';
import { AddDataSourcesLinesQuery } from './__generated__/AddDataSourcesLinesQuery.graphql';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { DataSourcesLinesPaginationQuery$variables } from '../data_sources/__generated__/DataSourcesLinesPaginationQuery.graphql';

const useStyles = makeStyles(() => ({
  createButton: {
    float: 'left',
    marginTop: -15,
  },
  search: {
    marginLeft: 'auto',
    marginRight: ' 20px',
  },
}));

const AddDataSources: FunctionComponent<{ dataComponentId: string }> = ({
  dataComponentId,
}) => {
  const { t } = useFormatter();
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
        color="secondary"
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
        title={t('Add data sources')}
        header={(
          <div className={classes.search}>
            <SearchInput
              variant="inDrawer"
              placeholder={`${t('Search')}...`}
              onSubmit={handleSearch}
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
      <DataSourceCreation
        contextual={true}
        display={open}
        inputValue={search}
        paginationOptions={paginationOptions}
      />
    </div>
  );
};

export default AddDataSources;
