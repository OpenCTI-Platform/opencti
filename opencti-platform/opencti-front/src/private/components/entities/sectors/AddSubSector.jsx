import React, { useState } from 'react';
import * as PropTypes from 'prop-types';
import IconButton from '@common/button/IconButton';
import { Add } from '@mui/icons-material';
import Drawer from '../../common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import AddSubSectorsLines, { addSubSectorsLinesQuery } from './AddSubSectorsLines';
import SectorCreation from './SectorCreation';
import SearchInput from '../../../../components/SearchInput';

const AddSubSector = (props) => {
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

  const { sector, sectorSubSectors } = props;
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
        title={t_i18n('Add subsectors')}
        onClose={handleClose}
      >
        <>
          <div>
            <SearchInput
              variant="small"
              onSubmit={handleSearch}
              keyword={search}
            />
            <div style={{ float: 'right' }}>
              <SectorCreation
                display={open}
                contextual={true}
                inputValue={search}
                paginationOptions={paginationOptions}
              />
            </div>
          </div>
          <QueryRenderer
            query={addSubSectorsLinesQuery}
            variables={{
              search: search,
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
};

AddSubSector.propTypes = {
  sector: PropTypes.object,
  sectorSubSectors: PropTypes.array,
};

export default AddSubSector;
