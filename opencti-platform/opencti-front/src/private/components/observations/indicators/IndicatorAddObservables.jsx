import IconButton from '@common/button/IconButton';
import { Add } from '@mui/icons-material';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Skeleton from '@mui/material/Skeleton';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { Component } from 'react';
import inject18n from '../../../../components/i18n';
import SearchInput from '../../../../components/SearchInput';
import { QueryRenderer } from '../../../../relay/environment';
import Drawer from '../../common/drawer/Drawer';
import StixCyberObservableCreation from '../stix_cyber_observables/StixCyberObservableCreation';
import IndicatorAddObservablesLines, { indicatorAddObservablesLinesQuery } from './IndicatorAddObservablesLines';

class IndicatorAddObservables extends Component {
  constructor(props) {
    super(props);
    this.state = { open: false, search: '' };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleClose() {
    this.setState({ open: false });
  }

  handleSearch(keyword) {
    this.setState({ search: keyword });
  }

  render() {
    const { t, indicator, indicatorObservables } = this.props;
    const paginationOptions = {
      search: this.state.search,
      orderBy: 'created_at',
      orderMode: 'desc',
    };
    return (
      <>
        <IconButton
          color="primary"
          aria-label="Add"
          onClick={this.handleOpen.bind(this)}
        >
          <Add fontSize="small" />
        </IconButton>
        <Drawer
          open={this.state.open}
          onClose={this.handleClose.bind(this)}
          title={t('Add observables')}
          header={(
            <SearchInput
              variant="inDrawer"
              onSubmit={this.handleSearch.bind(this)}
            />
          )}
        >
          <QueryRenderer
            query={indicatorAddObservablesLinesQuery}
            variables={{
              search: this.state.search,
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
          display={this.state.open}
          contextual={true}
          inputValue={this.state.search}
          paginationKey="Pagination_stixCyberObservables"
          paginationOptions={paginationOptions}
        />
      </>
    );
  }
}

IndicatorAddObservables.propTypes = {
  indicator: PropTypes.object,
  indicatorObservables: PropTypes.array,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

export default compose(inject18n)(IndicatorAddObservables);
