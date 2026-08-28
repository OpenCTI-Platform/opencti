import { useState } from 'react';
import IconButton from '@common/button/IconButton';
import { Add } from '@mui/icons-material';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Skeleton from '@mui/material/Skeleton';
import * as PropTypes from 'prop-types';
import { useFormatter } from '../../../../components/i18n';
import SearchInput from '../../../../components/SearchInput';
import { QueryRenderer } from '../../../../relay/environment';
import Drawer from '../../common/drawer/Drawer';
import StixCyberObservableCreation from '../stix_cyber_observables/StixCyberObservableCreation';
import IndicatorAddObservablesLines, { indicatorAddObservablesLinesQuery } from './IndicatorAddObservablesLines';

const IndicatorAddObservables = (props) => {
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState('');
  const handleOpen = () => {
    setOpen(true);
  };

  const handleClose = () => {
    setOpen(false);
  };

  const handleSearch = (keyword) => {
    setSearch(keyword);
  };

  const { indicator, indicatorObservables } = props;
  const paginationOptions = {
    search: search,
    orderBy: 'created_at',
    orderMode: 'desc',
  };
  return (
    <>
      <IconButton
        color="primary"
        aria-label="Add"
        onClick={handleOpen}
      >
        <Add fontSize="small" />
      </IconButton>
      <Drawer
        open={open}
        onClose={handleClose}
        title={t_i18n('Add observables')}
        subHeader={{
          left: [(
            <SearchInput
              variant="inDrawer"
              onSubmit={handleSearch}
              key="searchInput"
            />
          )],
        }}
      >
        <QueryRenderer
          query={indicatorAddObservablesLinesQuery}
          variables={{
            search: search,
            orderBy: 'created_at',
            orderMode: 'desc',
            count: 50,
          }}
          render={({ props }) => {
            if (props) {
              return (
                <IndicatorAddObservablesLines
                  indicator={indicator}
                  indicatorObservables={indicatorObservables}
                  data={props}
                />
              );
            }
            return (
              <List>
                {Array.from(Array(20), (e, i) => (
                  <ListItem key={i} divider={true}>
                    <ListItemIcon>
                      <Skeleton
                        animation="wave"
                        variant="circular"
                        width={30}
                        height={30}
                      />
                    </ListItemIcon>
                    <ListItemText
                      primary={(
                        <Skeleton
                          animation="wave"
                          variant="rectangular"
                          width="90%"
                          height={15}
                          style={{ marginBottom: 10 }}
                        />
                      )}
                      secondary={(
                        <Skeleton
                          animation="wave"
                          variant="rectangular"
                          width="90%"
                          height={15}
                        />
                      )}
                    />
                  </ListItem>
                ))}
              </List>
            );
          }}
        />
      </Drawer>
      <StixCyberObservableCreation
        display={open}
        contextual={true}
        inputValue={search}
        paginationKey="Pagination_stixCyberObservables"
        paginationOptions={paginationOptions}
      />
    </>
  );
};

IndicatorAddObservables.propTypes = {
  indicator: PropTypes.object,
  indicatorObservables: PropTypes.array,
  classes: PropTypes.object,
};

export default IndicatorAddObservables;
