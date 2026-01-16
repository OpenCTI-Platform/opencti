import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import IconButton from '@common/button/IconButton';
import { Add } from '@mui/icons-material';
import Drawer from '../../common/drawer/Drawer';
import inject18n from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import AddSubSectorsLines, { addSubSectorsLinesQuery } from './AddSubSectorsLines';
import SectorCreation from './SectorCreation';
import SearchInput from '../../../../components/SearchInput';

class AddSubSector extends Component {
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
    const { t, sector, sectorSubSectors } = this.props;
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
          title={t('Add subsectors')}
          onClose={this.handleClose.bind(this)}
        >
          <>
            <div>
              <SearchInput
                variant="small"
                onSubmit={this.handleSearch.bind(this)}
                keyword={this.state.search}
              />
              <div style={{ float: 'right' }}>
                <SectorCreation
                  display={this.state.open}
                  contextual={true}
                  inputValue={this.state.search}
                  paginationOptions={paginationOptions}
                />
              </div>
            </div>
            <QueryRenderer
              query={addSubSectorsLinesQuery}
              variables={{
                search: this.state.search,
                count: 20,
              }}
              render={({ props }) => {
                return (
                  <AddSubSectorsLines
                    sector={sector}
                    sectorSubSectors={sectorSubSectors}
                    data={props}
                  />
                );
              }}
            />
          </>
        </Drawer>
      </div>
    );
  }
}

AddSubSector.propTypes = {
  sector: PropTypes.object,
  sectorSubSectors: PropTypes.array,
  t: PropTypes.func,
};

export default compose(inject18n)(AddSubSector);
