import React, { useState } from 'react';
import * as PropTypes from 'prop-types';
import IconButton from '@common/button/IconButton';
import { Add } from '@mui/icons-material';
import Drawer from '../../common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import SearchInput from '../../../../components/SearchInput';
import { QueryRenderer } from '../../../../relay/environment';
import AddAttackPatternsLines, { addAttackPatternsLinesQuery } from './AddAttackPatternsLines';

const AddAttackPatterns = (props) => {
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

  const {

    courseOfAction,

    courseOfActionAttackPatterns,

    courseOfActionPaginationOptions,

  } = props;
  return (
    <div>
      <IconButton
        color="primary"
        aria-label="Attack Pattern"
        onClick={handleOpen}
      >
        <Add fontSize="small" />
      </IconButton>
      <Drawer
        open={open}
        onClose={handleClose}
        title={t_i18n('Add attack patterns')}
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
          query={addAttackPatternsLinesQuery}
          variables={{
            search: search,
            count: 20,
          }}
          render={({ props }) => {
            return (
              <AddAttackPatternsLines
                courseOfAction={courseOfAction}
                courseOfActionAttackPatterns={courseOfActionAttackPatterns}
                courseOfActionPaginationOptions={
                  courseOfActionPaginationOptions
                }
                data={props}
              />
            );
          }}
        />
      </Drawer>
    </div>
  );
};

AddAttackPatterns.propTypes = {
  courseOfAction: PropTypes.object,
  courseOfActionAttackPatterns: PropTypes.array,
  courseOfActionPaginationOptions: PropTypes.object,
  classes: PropTypes.object,
};

export default AddAttackPatterns;
