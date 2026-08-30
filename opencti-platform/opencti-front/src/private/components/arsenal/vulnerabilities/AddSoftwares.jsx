import React, { useState } from 'react';
import * as PropTypes from 'prop-types';
import IconButton from '@common/button/IconButton';
import { Add } from '@mui/icons-material';
import { useFormatter } from '../../../../components/i18n';
import SearchInput from '../../../../components/SearchInput';
import { QueryRenderer } from '../../../../relay/environment';
import AddSoftwaresLines, { addSoftwaresLinesQuery } from './AddSoftwaresLines';
import StixCyberObservableCreation from '../../observations/stix_cyber_observables/StixCyberObservableCreation';
import Drawer from '../../common/drawer/Drawer';

const AddSoftwares = (props) => {
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState('');
  const handleOpen = () => {
    setOpen(true);
  };

  const handleClose = () => {
    setOpen(false);
    setSearch('');
  };

  const handleSearch = (keyword) => {
    setSearch(keyword);
  };

  const { vulnerability, vulnerabilitySoftwares, relationshipType } = props;
  const paginationOptions = {
    search: search,
  };
  return (
    <div>
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
        title={t_i18n('Add software')}
        subHeader={{
          left: [(
            <SearchInput
              variant="inDrawer"
              onSubmit={handleSearch}
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
        display={open}
        contextual={true}
        inputValue={search}
        paginationOptions={{ ...paginationOptions, types: ['Software'] }}
        paginationKey="Pagination_stixCyberObservables"
        type="Software"
      />
    </div>
  );
};

AddSoftwares.propTypes = {
  vulnerability: PropTypes.object,
  vulnerabilitySoftwares: PropTypes.array,
  relationshipType: PropTypes.string,
  classes: PropTypes.object,
};

export default AddSoftwares;
