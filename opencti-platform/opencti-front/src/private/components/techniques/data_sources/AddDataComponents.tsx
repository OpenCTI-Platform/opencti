import React, { FunctionComponent, useState } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import IconButton from '@mui/material/IconButton';
import { Add, Close } from '@mui/icons-material';
import Drawer from '@mui/material/Drawer';
import Typography from '@mui/material/Typography';
import { useFormatter } from '../../../../components/i18n';
import { Theme } from '../../../../components/Theme';
import SearchInput from '../../../../components/SearchInput';
import AddDataComponentsLines, {
  addDataComponentsLinesQuery,
} from './AddDataComponentsLines';
import { AddAttackPatternsLinesToDataComponentQuery$variables } from '../data_components/__generated__/AddAttackPatternsLinesToDataComponentQuery.graphql';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { DataSourceDataComponents_dataSource$data } from './__generated__/DataSourceDataComponents_dataSource.graphql';
import { AddDataComponentsLinesToDataSourceQuery } from './__generated__/AddDataComponentsLinesToDataSourceQuery.graphql';
import DataComponentCreation from '../data_components/DataComponentCreation';

const useStyles = makeStyles<Theme>((theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
  createButton: {
    float: 'left',
    marginTop: -15,
  },
  title: {
    float: 'left',
  },
  search: {
    float: 'right',
  },
  header: {
    backgroundColor: theme.palette.background.nav,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
  container: {
    padding: 0,
  },
}));

const AddDataComponents: FunctionComponent<{
  dataSource: DataSourceDataComponents_dataSource$data;
}> = ({ dataSource }) => {
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

  const queryRef = useQueryLoading<AddDataComponentsLinesToDataSourceQuery>(
    addDataComponentsLinesQuery,
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
        anchor="right"
        elevation={1}
        sx={{ zIndex: 1202 }}
        classes={{ paper: classes.drawerPaper }}
        onClose={handleClose}
      >
        <div className={classes.header}>
          <IconButton
            aria-label="Close"
            className={classes.closeButton}
            onClick={handleClose}
            size="large"
            color="primary"
          >
            <Close fontSize="small" color="primary" />
          </IconButton>
          <Typography variant="h6" classes={{ root: classes.title }}>
            {t('Add data components')}
          </Typography>
          <div className={classes.search}>
            <SearchInput
              variant="inDrawer"
              placeholder={`${t('Search')}...`}
              onSubmit={handleSearch}
            />
          </div>
        </div>
        <div className={classes.container}>
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
        </div>
      </Drawer>
      <DataComponentCreation
        display={open}
        contextual={true}
        inputValue={search}
        paginationOptions={paginationOptions}
      />
    </div>
  );
};

export default AddDataComponents;
