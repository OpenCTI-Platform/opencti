import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import IconButton from '@common/button/IconButton';
import { Add } from '@mui/icons-material';
import inject18n from '../../../../components/i18n';
import SearchInput from '../../../../components/SearchInput';
import { QueryRenderer } from '../../../../relay/environment';
import AddSoftwaresLines, { addSoftwaresLinesQuery } from './AddSoftwaresLines';
import StixCyberObservableCreation from '../../observations/stix_cyber_observables/StixCyberObservableCreation';
import Drawer from '../../common/drawer/Drawer';

class AddSoftwares extends Component {
  constructor(props) {
    super(props);
    this.state = { open: false, search: '' };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleClose() {
    this.setState({ open: false, search: '' });
  }

  handleSearch(keyword) {
    this.setState({ search: keyword });
  }

  render() {
    const { t, vulnerability, vulnerabilitySoftwares, relationshipType } = this.props;
    const paginationOptions = {
      search: this.state.search,
    };
    return (
      <div>
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
          title={t('Add software')}
          subHeader={{
            left: [(
              <SearchInput
                variant="inDrawer"
                onSubmit={this.handleSearch.bind(this)}
                key="leftInput"
              />
            )],
          }}
        >
          <QueryRenderer
            query={addSoftwaresLinesQuery}
            variables={{ ...paginationOptions, count: 25 }}
            render={({ props }) => {
              return (
                <AddSoftwaresLines
                  vulnerability={vulnerability}
                  vulnerabilitySoftwares={vulnerabilitySoftwares}
                  relationshipType={relationshipType}
                  data={props}
                />
              );
            }}
          />
        </Drawer>
        <StixCyberObservableCreation
          display={this.state.open}
          contextual={true}
          inputValue={this.state.search}
          paginationOptions={{ ...paginationOptions, types: ['Software'] }}
          paginationKey="Pagination_stixCyberObservables"
          type="Software"
        />
      </div>
    );
  }
}

AddSoftwares.propTypes = {
  vulnerability: PropTypes.object,
  vulnerabilitySoftwares: PropTypes.array,
  relationshipType: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(inject18n)(AddSoftwares);
