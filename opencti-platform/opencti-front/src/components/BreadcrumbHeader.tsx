import React, { FunctionComponent, useEffect, useState } from 'react';
import { Breadcrumbs, Divider, Link, ListItemText, MenuItem, MenuList, Typography } from '@mui/material';
import { Link as ReactRouterLink, useLocation } from 'react-router-dom';
import useGranted from 'src/utils/hooks/useGranted';
import { makeStyles } from '@mui/styles';
import { RulesType, allTypes } from '@components/nav/Menu';
import { StyledTooltip } from '@components/nav/LeftBar';
import { useFormatter } from './i18n';

const useStyles = makeStyles(() => ({
  tooltipHeader: {
    padding: '0 8px',
    fontSize: '15px',
    fontWeight: 'bold',
  },
  tooltipMenuItem: {
    margin: 0,
    padding: '4px 8px',
    minHeight: '20px',
  },
}));

interface TooltipTextProps {
  entity_type: string
}

export const TooltipText: FunctionComponent<TooltipTextProps> = ({ entity_type }) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const location = useLocation();
  const isSelected = (record: RulesType) => {
    if (record.name === 'Parameters') {
      return location.pathname.endsWith('/dashboard/settings')
        || location.pathname.endsWith('/dashboard/settings/');
    }
    return location.pathname.includes(`/dashboard/${entity_type.toLowerCase()}/${record.pathname}`);
  };
  const isGranted = (record: RulesType) => {
    return record.needs
      ? useGranted(record.needs)
      : true;
  };
  return (
    <MenuList>
      <div className={ classes.tooltipHeader }>{t_i18n(entity_type)}</div>
      <Divider light />
      {Object.values(allTypes[entity_type]).map((record) => (isGranted(record)
        ? <MenuItem
            component={ReactRouterLink}
            to={`/dashboard/${entity_type.toLowerCase()}/${record.pathname}`}
            selected={isSelected(record)}
            dense={true}
            key={record.name}
            classes={{ root: classes.tooltipMenuItem }}
          >
          <ListItemText>
            <div style={{
              fontWeight: isSelected(record)
                ? 'bold'
                : 'normal',
            }}
            >
              {t_i18n(record.name)}
            </div>
          </ListItemText>
        </MenuItem>
        : ''
      ))}
    </MenuList>
  );
};

interface BreadcrumbHeaderProps {
  path: {
    text: string,
    link?: string,
  }[],
  children: JSX.Element,
}

const BreadcrumbHeader: FunctionComponent<BreadcrumbHeaderProps> = ({
  path: defaultPath,
  children,
}) => {
  const [path, setPath] = useState(defaultPath);

  useEffect(() => {
    setPath(defaultPath);
  }, [defaultPath]);

  return (<div>
    <Breadcrumbs>
      {<StyledTooltip title={TooltipText({ entity_type: path[0].text })}>
        <div style={{ fontSize: '13px', fontWeight: 'bold' }}>
          {path[0].text}
        </div>
      </StyledTooltip>}
      {path.slice(1).map((p) => (p.link
        ? <Link
            component={ReactRouterLink}
            underline="always"
            color="inherit"
            to={p.link}
            key={p.text}
          >
          <div style={{ fontSize: '13px' }}>{p.text}</div>
        </Link>
        : <Typography key={p.text} style={{ fontSize: '13px' }}>{p.text}</Typography>))}
    </Breadcrumbs>
    {children}
  </div>);
};

export default BreadcrumbHeader;
