import { KeyboardArrowRightOutlined } from '@mui/icons-material';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Skeleton from '@mui/material/Skeleton';
import { styled } from '@mui/material/styles';
import React, { FunctionComponent } from 'react';
import { DataColumns } from '../../../../components/list_lines';
import { Checkbox } from '@filigran/design-system';
import { bodyItemStyle } from '../../../../components/list_lines/listLineStyles';

const BodyItem = styled('div')(bodyItemStyle);

interface CaseTemplateLineDummyProps {
  dataColumns: DataColumns;
}

const CaseTemplateLineDummy: FunctionComponent<CaseTemplateLineDummyProps> = ({ dataColumns }) => {
  return (
    <ListItem sx={{ paddingLeft: '10px', height: 50, cursor: 'default' }} divider={true}>
      <ListItemIcon
        sx={{ color: 'grey.700' }}
        style={{ minWidth: 40 }}
      >
        <Checkbox
          disabled={true}
        />
      </ListItemIcon>
      <ListItemIcon sx={{ color: 'grey.700' }}>
        <Skeleton animation="wave" variant="circular" width={30} height={30} />
      </ListItemIcon>
      <ListItemText
        primary={(
          <div>
            {Object.values(dataColumns).map(({ label, width }) => (
              <BodyItem
                key={label}
                style={{ width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width={width}
                  height="100%"
                />
              </BodyItem>
            ))}
          </div>
        )}
      />
      <ListItemIcon sx={{ position: 'absolute', right: -10 }}>
        <KeyboardArrowRightOutlined />
      </ListItemIcon>
    </ListItem>
  );
};

export default CaseTemplateLineDummy;
