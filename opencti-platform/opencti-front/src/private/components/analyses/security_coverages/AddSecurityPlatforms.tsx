import React, { FunctionComponent, useState } from 'react';
import { Theme } from '@mui/material/styles/createTheme';
import makeStyles from '@mui/styles/makeStyles';
import IconButton from '@mui/material/IconButton';
import { Add } from '@mui/icons-material';
import Drawer from '../../common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import SearchInput from '../../../../components/SearchInput';
import { QueryRenderer } from '../../../../relay/environment';
import AddSecurityPlatformsLines, { addSecurityPlatformsLinesQuery } from './AddSecurityPlatformsLines';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>(() => ({
  createButton: {
    float: 'left',
    marginTop: -15,
  },
}));

interface AddSecurityPlatformsProps {
  securityCoverage: {
    id: string;
  };
  securityCoverageSecurityPlatforms: ReadonlyArray<{
    readonly node: {
      readonly id: string;
    };
  }> | Array<{
    node: {
      id: string;
    };
  }>;
}

const AddSecurityPlatforms: FunctionComponent<AddSecurityPlatformsProps> = ({
  securityCoverage,
  securityCoverageSecurityPlatforms,
}) => {
  const classes = useStyles();
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

  const handleSearch = (keyword: string) => {
    setSearch(keyword);
  };

  return (
    <>
      <IconButton
        color="primary"
        aria-label="Add"
        onClick={handleOpen}
        classes={{ root: classes.createButton }}
        size="large"
      >
        <Add fontSize="small" />
      </IconButton>
      <Drawer
        open={open}
        onClose={handleClose}
        title={t_i18n('Add security platforms')}
        header={(
          <div
            style={{
              marginLeft: 'auto',
              marginRight: '20px',
              display: 'flex',
              flexDirection: 'column',
            }}
          >
            <SearchInput
              variant="thin"
              onSubmit={handleSearch}
            />
          </div>
        )}
      >
        {open ? (
          <QueryRenderer
            query={addSecurityPlatformsLinesQuery}
            variables={{
              search,
              count: 20,
            }}
            render={({ props }: any) => {
              if (props) {
                return (
                  <AddSecurityPlatformsLines
                    securityCoverage={securityCoverage}
                    securityCoverageSecurityPlatforms={securityCoverageSecurityPlatforms as any}
                    data={props}
                  />
                );
              }
              return <div />;
            }}
          />
        ) : null}
      </Drawer>
    </>
  );
};

export default AddSecurityPlatforms;
