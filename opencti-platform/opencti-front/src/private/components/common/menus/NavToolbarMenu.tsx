import React, { FunctionComponent, ReactElement, useEffect, useRef, useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import Drawer from '@mui/material/Drawer';
import MenuList from '@mui/material/MenuList';
import MenuItem from '@mui/material/MenuItem';
import ListItemText from '@mui/material/ListItemText';
import ListItemIcon from '@mui/material/ListItemIcon';
import { styled } from '@mui/material/styles';
import Tooltip from '@mui/material/Tooltip';
import EEChip from '@components/common/entreprise_edition/EEChip';
import { Stack } from '@mui/material';
import Box from '@mui/material/Box';
import { useFormatter } from '../../../../components/i18n';
import useAuth from '../../../../utils/hooks/useAuth';
import { useSettingsMessagesBannerHeight } from '../../settings/settings_messages/SettingsMessagesBanner';

const StyledDrawer = styled(Drawer)(() => ({
  '& .MuiDrawer-paper': {
    minHeight: '100vh',
    width: 200,
    position: 'fixed',
    overflow: 'auto',
    padding: 0,
    zIndex: 998,
  },
}));

const ToolbarSpacer = styled('div')(({ theme }) => ({
  ...theme.mixins.toolbar,
}));

export interface MenuEntry {
  path: string;
  label: string;
  icon?: ReactElement;
  isEE?: boolean;
}

const TruncatedText: FunctionComponent<{ children: React.ReactNode }> = ({ children }) => {
  const textRef = useRef<HTMLDivElement>(null);
  const [isTruncated, setIsTruncated] = useState(false);

  useEffect(() => {
    const textElement = textRef.current;
    if (textElement) {
      setIsTruncated(textElement.scrollWidth > textElement.clientWidth);
    }
  }, [children]);

  const content = (
    <Box
      sx={{ overflow: 'hidden', textOverflow: 'ellipsis' }}
      ref={textRef}
    >
      {children}
    </Box>
  );

  if (isTruncated) {
    return (
      <Tooltip title={children} arrow placement="left-start">
        {content}
      </Tooltip>
    );
  }

  return content;
};

const NavToolbarMenu: FunctionComponent<{ entries: MenuEntry[] }> = ({ entries }) => {
  const { t_i18n } = useFormatter();
  const location = useLocation();
  const { bannerSettings } = useAuth();
  const settingsMessagesBannerHeight = useSettingsMessagesBannerHeight();

  const bannerHeight = bannerSettings.bannerHeightNumber;

  const renderLabel = (entry: MenuEntry) => {
    const translatedLabel = t_i18n(entry.label);

    if (entry.isEE) {
      return (
        <Stack direction="row">
          <TruncatedText>{translatedLabel}</TruncatedText>
          <EEChip />
        </Stack>
      );
    }

    return <TruncatedText>{translatedLabel}</TruncatedText>;
  };

  return (
    <StyledDrawer variant="permanent" anchor="right">
      <ToolbarSpacer />

      <MenuList component="nav" style={{ marginTop: bannerHeight + settingsMessagesBannerHeight, marginBottom: bannerHeight }}>
        {entries.map((entry, idx) => {
          return (
            <MenuItem
              key={idx}
              component={Link}
              to={entry.path}
              selected={location.pathname.startsWith(entry.path)}
              dense={false}
              sx={{ paddingRight: 0 }}
            >
              {entry.icon && (
                <ListItemIcon>{entry.icon}</ListItemIcon>
              )}
              <ListItemText primary={renderLabel(entry)} />
            </MenuItem>
          );
        })}
      </MenuList>
    </StyledDrawer>
  );
};

export default NavToolbarMenu;
