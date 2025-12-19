import makeStyles from '@mui/styles/makeStyles';
import React, { FunctionComponent, useState } from 'react';
import IconButton from '@common/button/IconButton';
import { Add } from '@mui/icons-material';
import Drawer from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import SearchInput from '../../../../components/SearchInput';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import AddDataComponentsLines, { addDataComponentsLinesQuery } from './AddDataComponentsLines';
import { AddDataComponentsLinesQuery, AddDataComponentsLinesQuery$variables } from './__generated__/AddDataComponentsLinesQuery.graphql';
import { AttackPatternDataComponents_attackPattern$data } from './__generated__/AttackPatternDataComponents_attackPattern.graphql';
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
  attackPattern: AttackPatternDataComponents_attackPattern$data;
}> = ({ attackPattern }) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState('');
  const paginationOptions: AddDataComponentsLinesQuery$variables = {
    search,
    count: 20,
  };
  const handleSearch = (keyword: string) => setSearch(keyword);
  const handleOpen = () => setOpen(true);
  const handleClose = () => {
    setOpen(false);
    setSearch('');
  };
  const queryRef = useQueryLoading<AddDataComponentsLinesQuery>(
    addDataComponentsLinesQuery,
    paginationOptions,
  );
  return (
    <>
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
          <div
            style={{
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
            <AddDataComponentsLines
              attackPattern={attackPattern}
              queryRef={queryRef}
            />
          </React.Suspense>
        )}
      </Drawer>
    </>
  );
};

export default AddDataComponents;
