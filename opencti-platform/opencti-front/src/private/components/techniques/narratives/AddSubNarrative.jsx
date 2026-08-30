import React, { useState } from 'react';
import * as PropTypes from 'prop-types';
import IconButton from '@common/button/IconButton';
import { Add } from '@mui/icons-material';
import Drawer from '../../common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import SearchInput from '../../../../components/SearchInput';
import { QueryRenderer } from '../../../../relay/environment';
import AddSubNarrativesLines, { addSubNarrativesLinesQuery } from './AddSubNarrativesLines';
import NarrativeCreation from './NarrativeCreation';

const AddSubNarrative = (props) => {
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

  const { narrative, narrativeSubNarratives } = props;
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
        title={t_i18n('Add subnarratives')}
        subHeader={{
          right: [(
            <NarrativeCreation
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
          query={addSubNarrativesLinesQuery}
          variables={{
            search: search,
            count: 20,
          }}
          render={({ props }) => {
            return (
              <AddSubNarrativesLines
                narrative={narrative}
                narrativeSubNarratives={narrativeSubNarratives}
                data={props}
              />
            );
          }}
        />
      </Drawer>
    </div>
  );
};

AddSubNarrative.propTypes = {
  narrative: PropTypes.object,
  narrativeSubNarratives: PropTypes.array,
  classes: PropTypes.object,
};

export default AddSubNarrative;
