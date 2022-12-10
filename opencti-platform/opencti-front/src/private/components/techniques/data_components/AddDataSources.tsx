import React, { FunctionComponent, useState } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import IconButton from '@mui/material/IconButton';
import { Add, Close } from '@mui/icons-material';
import Drawer from '@mui/material/Drawer';
import Typography from '@mui/material/Typography';
import { useFormatter } from '../../../../components/i18n';
import { Theme } from '../../../../components/Theme';
import DataSourceCreation from '../data_sources/DataSourceCreation';
import SearchInput from '../../../../components/SearchInput';
import AddDataSourcesLines, { addDataSourcesLinesQuery } from './AddDataSourcesLines';
import { AddDataSourcesLinesQuery } from './__generated__/AddDataSourcesLinesQuery.graphql';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { DataSourcesLinesPaginationQuery$variables } from '../data_sources/__generated__/DataSourcesLinesPaginationQuery.graphql';

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
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.grey?.[700],
  },
  avatar: {
    width: 24,
    height: 24,
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

  const queryRef = useQueryLoading<AddDataSourcesLinesQuery>(addDataSourcesLinesQuery, { ...paginationOptions });

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
            {t('Add data source')}
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
            <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
              <AddDataSourcesLines
                dataComponentId={dataComponentId}
                queryRef={queryRef}
              />
            </React.Suspense>
          )}
        </div>
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
