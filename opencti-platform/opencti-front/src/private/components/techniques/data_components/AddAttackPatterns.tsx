import makeStyles from '@mui/styles/makeStyles';
import React, { FunctionComponent, useState } from 'react';
import IconButton from '@mui/material/IconButton';
import { Add } from '@mui/icons-material';
import Drawer from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import SearchInput from '../../../../components/SearchInput';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { DataComponentAttackPatterns_dataComponent$data } from './__generated__/DataComponentAttackPatterns_dataComponent.graphql';
import { AddAttackPatternsLinesToDataComponentQuery, AddAttackPatternsLinesToDataComponentQuery$variables } from './__generated__/AddAttackPatternsLinesToDataComponentQuery.graphql';
import AddAttackPatternsLines, { addAttackPatternsLinesQuery } from './AddAttackPatternsLines';

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

const AddAttackPatterns: FunctionComponent<{
  dataComponent: DataComponentAttackPatterns_dataComponent$data;
}> = ({ dataComponent }) => {
  const { t } = useFormatter();
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

  const queryRef = useQueryLoading<AddAttackPatternsLinesToDataComponentQuery>(
    addAttackPatternsLinesQuery,
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
        title={t('Add attack patterns')}
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
            <AddAttackPatternsLines
              dataComponent={dataComponent}
              queryRef={queryRef}
            />
          </React.Suspense>
        )}
      </Drawer>
    </div>
  );
};

export default AddAttackPatterns;
