import React, { useState } from 'react';
import * as PropTypes from 'prop-types';
import IconButton from '@common/button/IconButton';
import { Add } from '@mui/icons-material';
import Drawer from '../../common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import SearchInput from '../../../../components/SearchInput';
import { QueryRenderer } from '../../../../relay/environment';
import AddSubAttackPatternsLines, { addSubAttackPatternsLinesQuery } from './AddSubAttackPatternsLines';
import AttackPatternCreation from './AttackPatternCreation';

const AddSubAttackPattern = (props) => {
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

  const { attackPattern, attackPatternSubAttackPatterns } = props;
  const paginationOptions = {
    search: search,
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
        title={t_i18n('Add sub attack patterns')}
        subHeader={{
          right: [(
            <AttackPatternCreation
              display={open}
              contextual={true}
              inputValue={search}
              paginationOptions={paginationOptions}
              key="rightButton"
            />
          )],
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
          query={addSubAttackPatternsLinesQuery}
          variables={{
            search: search,
            count: 20,
          }}
          render={({ props }) => {
            return (
              <AddSubAttackPatternsLines
                attackPattern={attackPattern}
                attackPatternSubAttackPatterns={
                  attackPatternSubAttackPatterns
                }
                data={props}
              />
            );
          }}
        />
      </Drawer>
    </>
  );
};

AddSubAttackPattern.propTypes = {
  attackPattern: PropTypes.object,
  attackPatternSubAttackPatterns: PropTypes.array,
  classes: PropTypes.object,
};

export default AddSubAttackPattern;
