import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link } from 'react-router';
import { styled } from '@mui/material/styles';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { KeyboardArrowRightOutlined } from '@mui/icons-material';
import { map } from 'ramda';
import List from '@mui/material/List';
import { ListItemButton } from '@mui/material';
import Skeleton from '@mui/material/Skeleton';
import { DraftChip } from '../../common/draft/DraftChip';
import inject18n from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';

const Name = styled('div')({
  width: '20%',
  lineHeight: '28px',
  float: 'left',
  whiteSpace: 'nowrap',
  overflow: 'hidden',
  textOverflow: 'ellipsis',
});

const Description = styled('div')({
  width: '70%',
  lineHeight: '28px',
  float: 'left',
  whiteSpace: 'nowrap',
  overflow: 'hidden',
  textOverflow: 'ellipsis',
  color: '#a5a5a5',
  fontSize: 12,
});

const itemIconSx = {
  color: (theme) => theme.palette.primary.main,
};

const goIconSx = {
  position: 'absolute',
  right: -10,
};

class SectorLineComponent extends Component {
  render() {
    const { subSectors, node, isSubSector, t } = this.props;
    return (
      <div>
        <ListItemButton
          sx={isSubSector ? { paddingLeft: 4 } : undefined}
          divider={true}
          component={Link}
          to={`/dashboard/entities/sectors/${node.id}`}
        >
          <ListItemIcon sx={itemIconSx}>
            <ItemIcon type="Sector" size={isSubSector ? 'small' : 'medium'} />
          </ListItemIcon>
          <ListItemText
            sx={{ margin: 0, height: '28px' }}
            primary={(
              <div>
                <Name>
                  {node.name}
                  {node.draftVersion && (<DraftChip style={{ verticalAlign: 1 }} />)}
                </Name>
                <Description>
                  {node.description?.length > 0
                    ? node.description
                    : t('This sector does not have any description.')}
                </Description>
              </div>
            )}
          />
          <ListItemIcon sx={goIconSx}>
            <KeyboardArrowRightOutlined />
          </ListItemIcon>
        </ListItemButton>
        {subSectors && subSectors.length > 0 && (
          <List style={{ margin: 0, padding: 0 }}>
            {map(
              (subSector) => (

                <SectorLine
                  key={subSector.id}
                  node={subSector}
                  isSubSector={true}
                />
              ),
              subSectors,
            )}
          </List>
        )}
      </div>
    );
  }
}

SectorLineComponent.propTypes = {
  node: PropTypes.object,
  isSubSector: PropTypes.bool,
  subSectors: PropTypes.array,
  fd: PropTypes.func,
};

export const SectorLine = inject18n(SectorLineComponent);

class SectorLineDummyComponent extends Component {
  render() {
    return (
      <ListItem divider={true}>
        <ListItemIcon sx={itemIconSx}>
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
              height={20}
            />
          )}
        />
        <ListItemIcon sx={goIconSx}>
          <KeyboardArrowRightOutlined />
        </ListItemIcon>
      </ListItem>
    );
  }
}

export const SectorLineDummy = inject18n(SectorLineDummyComponent);
