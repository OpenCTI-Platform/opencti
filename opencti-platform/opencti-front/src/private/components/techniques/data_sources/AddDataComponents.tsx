import React, { FunctionComponent, useState } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import IconButton from '@common/button/IconButton';
import { Add } from '@mui/icons-material';
import Drawer from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import SearchInput from '../../../../components/SearchInput';
import AddDataComponentsLines, { addDataComponentsLinesQuery } from './AddDataComponentsLines';
import { AddAttackPatternsLinesToDataComponentQuery$variables } from '../data_components/__generated__/AddAttackPatternsLinesToDataComponentQuery.graphql';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { DataSourceDataComponents_dataSource$data } from './__generated__/DataSourceDataComponents_dataSource.graphql';
import { AddDataComponentsLinesToDataSourceQuery } from './__generated__/AddDataComponentsLinesToDataSourceQuery.graphql';
import DataComponentCreation from '../data_components/DataComponentCreation';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  createButton: {
    float: 'left',
    marginTop: -15,
  },
}));

const AddDataComponents: FunctionComponent<{
  dataSource: DataSourceDataComponents_dataSource$data;
}> = ({ dataSource }) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();

  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState('');
  const paginationOptions: AddAttackPatternsLinesToDataComponentQuery$variables = {
    search,
    count: 20,
  };

  const handleSearch = (keyword: string) => setSearch(keyword);
  const handleOpen = () => setOpen(true);
  const handleClose = () => {
    setOpen(false);
    setSearch('');
  };

  const queryRef = useQueryLoading<AddDataComponentsLinesToDataSourceQuery>(
    addDataComponentsLinesQuery,
    { ...paginationOptions },
  );

  return (
    <div>
      <IconButton
        color="primary"
        aria-label="Add"
        onClick={handleOpen}
        classes={{ root: classes.createButton }}
      >
        <Add fontSize="small" />
      </IconButton>
      <Drawer
        open={open}
        onClose={handleClose}
        title={t_i18n('Add data components')}
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
            <DataComponentCreation
              display={open}
              contextual={true}
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
            <AddDataComponentsLines
              dataSource={dataSource}
              queryRef={queryRef}
            />
          </React.Suspense>
        )}
      </Drawer>
    </div>
  );
};

export default AddDataComponents;
