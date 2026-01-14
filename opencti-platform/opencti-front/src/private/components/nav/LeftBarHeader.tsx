import IconButton from '@common/button/IconButton';
import { ArrowDropDown, OpenInNew } from '@mui/icons-material';
import { Box, Divider, List, ListItemButton, ListItemIcon, Popover, Tooltip } from '@mui/material';
import { useTheme } from '@mui/styles';
import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { useFormatter } from '../../../components/i18n';
import logoOpenAEV from '../../../static/images/logo_open_aev.svg';
import logoXTMHub from '../../../static/images/logo_xtm_hub.svg';
import { isNotEmptyField } from '../../../utils/utils';
import { Theme } from '../../../components/Theme';

interface PopoverListItemProps {
  logoSrc: string;
  href?: string;
  to?: string;
  external?: boolean;
  onClick?: () => void;
}

export const PopoverListItem: React.FC<PopoverListItemProps> = ({
  logoSrc,
  href,
  to,
  external,
  onClick,
}) => {
  const theme = useTheme<Theme>();
  const Component = href ? 'a' : to ? Link : 'div';

  return (
    <ListItemButton
      component={Component}
      href={href}
      to={to}
      target={external ? '_blank' : undefined}
      rel={external ? 'noopener noreferrer' : undefined}
      onClick={onClick}
      sx={{
        borderRadius: 1,
        px: 1,
        py: 1.5,
        display: 'flex',
        justifyContent: 'space-between',
        backgroundColor: theme.palette.leftBar.header.itemBackground,
      }}
    >
      <ListItemIcon sx={{ width: 132, p: 1 }}>
        <Box
          sx={{
            width: '100%',
            height: '20px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}
        >
          <img
            src={logoSrc}
            style={{
              width: '100%',
              height: 'auto',
              objectFit: 'contain',
            }}
          />
        </Box>

      </ListItemIcon>

      {external && (
        <OpenInNew
          style={{
            fontSize: 16,
          }}
        />
      )}
    </ListItemButton>
  );
};

interface LeftBarHeaderProps {
  logo: string;
  logoCollapsed?: string;
  navOpen: boolean;
  bannerHeightNumber: number;
  settingsMessagesBannerHeight: number;
  openAEVUrl?: string;
  xtmhubUrl?: string;
  xtmhubStatus?: string;
  hasXtmHubAccess?: boolean;
}

export const LeftBarHeader: React.FC<LeftBarHeaderProps> = ({
  logo,
  logoCollapsed,
  navOpen,
  bannerHeightNumber,
  settingsMessagesBannerHeight,
  openAEVUrl,
  xtmhubUrl,
  xtmhubStatus,
  hasXtmHubAccess,
}) => {
  const { t_i18n } = useFormatter();

  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const open = Boolean(anchorEl);

  const currentLogo = navOpen ? logo : (logoCollapsed || logo);

  const handleMouseLeave = () => {
    setAnchorEl(null);
  };

  const handleClickPopover = (event: React.MouseEvent<HTMLElement>) => {
    event.preventDefault();
    event.stopPropagation();
    if (open) {
      setAnchorEl(null);
    } else {
      setAnchorEl(event.currentTarget);
    }
  };

  return (
    <>
      <Box
        component={Link}
        to="/dashboard"
        style={{
          marginTop: `calc(${bannerHeightNumber}px + ${settingsMessagesBannerHeight}px)`,
        }}
        sx={{
          padding: navOpen ? 2 : '16px 0',
          paddingRight: navOpen ? 1 : 0,
          width: '100%',
          flexShrink: 0,
          display: 'flex',
          alignItems: 'center',
          gap: 1,
          justifyContent: navOpen ? 'space-between' : 'center',
          '&:hover': {
            cursor: 'pointer',
          },
        }}
      >
        <img
          src={currentLogo}
          alt="logo"
          style={{
            height: 35,
            maxWidth: navOpen ? '110px' : '23px',
            objectFit: 'contain',
          }}
        />

        {navOpen && (
          <IconButton onClick={handleClickPopover}>
            <ArrowDropDown
              sx={{
                transform: open ? 'rotate(180deg)' : 'rotate(0deg)',
                transition: 'transform 0.2s',
              }}
            />
          </IconButton>
        )}
      </Box>

      <Popover
        open={open}
        anchorEl={anchorEl}
        anchorOrigin={{
          vertical: 'bottom',
          horizontal: 'right',
        }}
        transformOrigin={{
          vertical: 'top',
          horizontal: 'left',
        }}
        sx={{
          transform: 'translateX(-40px)',
        }}
        onClose={handleMouseLeave}
      >
        <List
          className="left-bar-header"
          dense
          disablePadding
          sx={{
            minWidth: 228,
          }}
        >
          <Tooltip title={isNotEmptyField(openAEVUrl) ? t_i18n('Platform connected') : t_i18n('Get OpenAEV now')}>
            <span>
              <PopoverListItem
                logoSrc={logoOpenAEV}
                href={openAEVUrl}
                external
                onClick={handleMouseLeave}
              />
            </span>
          </Tooltip>

          <Divider />

          {(xtmhubStatus === 'registered' || !hasXtmHubAccess) ? (
            <PopoverListItem
              logoSrc={logoXTMHub}
              href={isNotEmptyField(xtmhubUrl) ? xtmhubUrl : 'https://hub.filigran.io'}
              external
              onClick={handleMouseLeave}
            />
          ) : (
            <PopoverListItem
              logoSrc={logoXTMHub}
              to="/dashboard/settings/experience"
              onClick={handleMouseLeave}
            />
          )}
        </List>
      </Popover>
    </>
  );
};
