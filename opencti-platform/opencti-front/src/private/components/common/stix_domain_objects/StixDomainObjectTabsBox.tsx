import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab, { TabProps } from '@mui/material/Tab';
import { Link, useLocation } from 'react-router-dom';
import React, { MouseEvent, ReactNode, useState } from 'react';
import { getCurrentTab } from '../../../../utils/utils';
import { useFormatter } from '../../../../components/i18n';
import { useCustomViews } from '../../custom_views/useCustomViews';
import Menu from '@mui/material/Menu';
import { MenuItem, PopoverProps } from '@mui/material';
import { ArrowDropDown, ArrowDropUp } from '@mui/icons-material';

type TabWithDropDownMenuProps = TabProps & {
  MenuItems: ReactNode[];
};

const TabWithDropDownMenu = (props: TabWithDropDownMenuProps) => {
  const { t_i18n } = useFormatter();
  const [anchorPopover, setAnchorPopover] = useState<PopoverProps['anchorEl']>(null);

  const onOpenPopover = (event: MouseEvent) => {
    event.stopPropagation();
    setAnchorPopover(event.currentTarget);
  };

  const onClosePopover = (event: MouseEvent) => {
    event.stopPropagation();
    setAnchorPopover(null);
  };
  return (
    <>
      <Tab
        component="div"
        value={props.value}
        icon={anchorPopover ? <ArrowDropUp sx={{ fontSize: '20px' }} /> : <ArrowDropDown sx={{ fontSize: '20px' }} />}
        iconPosition="end"
        label={props.label}
        onClick={onOpenPopover}
      />
      <Menu
        anchorEl={anchorPopover}
        open={Boolean(anchorPopover)}
        onClose={onClosePopover}
        aria-label={t_i18n('Popover menu')}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
        transformOrigin={{ vertical: 'top', horizontal: 'right' }}
      >
        {props.MenuItems}
      </Menu>
    </>
  );
};

export type StixDomainObjectTabsBoxTab
  = | 'overview'
    | 'knowledge'
    | 'content'
    | 'analyses'
    | 'sightings'
    | 'entities'
    | 'observables'
    | 'files'
    | 'history';

interface StixDomainObjectTabsBoxProps {
  entity: { id: string; entity_type: string };
  basePath: string;
  tabs: StixDomainObjectTabsBoxTab[];
  extraActions?: React.ReactNode;
}

const StixDomainObjectTabsBox = ({ basePath, entity, extraActions, tabs }: StixDomainObjectTabsBoxProps) => {
  const { t_i18n } = useFormatter();
  const location = useLocation();
  const { customViews } = useCustomViews(entity.entity_type);
  return (
    <Box
      sx={{
        borderBottom: 1,
        borderColor: 'divider',
        marginBottom: 3,
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
      }}
    >
      <Tabs
        textColor="primary"
        value={getCurrentTab(location.pathname, entity.id, basePath)}
      >
        {tabs.includes('overview') && (
          <Tab
            component={Link}
            to={`${basePath}/${entity.id}`}
            value={`${basePath}/${entity.id}`}
            label={t_i18n('Overview')}
          />
        )}
        {tabs.includes('knowledge') && (
          <Tab
            component={Link}
            to={`${basePath}/${entity.id}/knowledge`}
            value={`${basePath}/${entity.id}/knowledge`}
            label={t_i18n('Knowledge')}
          />
        )}
        {tabs.includes('content') && (
          <Tab
            component={Link}
            to={`${basePath}/${entity.id}/content`}
            value={`${basePath}/${entity.id}/content`}
            label={t_i18n('Content')}
          />
        )}
        {tabs.includes('analyses') && (
          <Tab
            component={Link}
            to={`${basePath}/${entity.id}/analyses`}
            value={`${basePath}/${entity.id}/analyses`}
            label={t_i18n('Analyses')}
          />
        )}
        {tabs.includes('sightings') && (
          <Tab
            component={Link}
            to={`${basePath}/${entity.id}/sightings`}
            value={`${basePath}/${entity.id}/sightings`}
            label={t_i18n('Sightings')}
          />
        )}
        {tabs.includes('entities') && (
          <Tab
            component={Link}
            to={`${basePath}/${entity.id}/entities`}
            value={`${basePath}/${entity.id}/entities`}
            label={t_i18n('Entities')}
          />
        )}
        {tabs.includes('observables') && (
          <Tab
            component={Link}
            to={`${basePath}/${entity.id}/observables`}
            value={`${basePath}/${entity.id}/observables`}
            label={t_i18n('Observables')}
          />
        )}
        {tabs.includes('files') && (
          <Tab
            component={Link}
            to={`${basePath}/${entity.id}/files`}
            value={`${basePath}/${entity.id}/files`}
            label={t_i18n('Data')}
          />
        )}
        {tabs.includes('history') && (
          <Tab
            component={Link}
            to={`${basePath}/${entity.id}/history`}
            value={`${basePath}/${entity.id}/history`}
            label={t_i18n('History')}
          />
        )}
        {customViews.length === 1 ? (
          <Tab
            component={Link}
            to={`${basePath}/${entity.id}/custom-views/${customViews[0].id}`}
            value={`${basePath}/${entity.id}/custom-views`}
            label={customViews[0].name}
          />
        ) : customViews.length > 1 ? (
          <TabWithDropDownMenu
            value={`${basePath}/${entity.id}/custom-views`}
            label="Custom views"
            MenuItems={
              customViews.map(({ id, name }) => (
                <MenuItem
                  key={id}
                  style={{
                    padding: 0,
                  }}
                >
                  <Link
                    style={{
                      padding: '10px',
                    }}
                    to={`${basePath}/${entity.id}/custom-views/${customViews[0].id}`}
                  >{name}
                  </Link>
                </MenuItem>
              ))
            }
          />
        ) : null
        }
      </Tabs>
      {extraActions ? (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '10px' }}>
          {extraActions}
        </div>
      ) : null}
    </Box>
  );
};

export default StixDomainObjectTabsBox;
