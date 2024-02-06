import React, { FunctionComponent } from 'react';
import MUIBreadcrumbs from '@mui/material/Breadcrumbs';
import { Link } from 'react-router-dom';
import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import { useTheme } from '@mui/styles';
import type { Theme } from '@mui/material/styles/createTheme';

interface element {
  label: string;
  link?: string;
  current?: boolean;
}

interface BreadcrumpsProps {
  variant: 'list' | 'object',
  elements: element[],
}

const useStyles = makeStyles(() => ({
  breadcrumbsList: {
    marginTop: -5,
    marginBottom: 25,
  },
  breadcrumbsObject: {
    marginTop: -5,
    marginBottom: 15,
  },
}));

const Breadcrumps: FunctionComponent<BreadcrumpsProps> = ({ elements, variant }) => {
  const theme = useTheme<Theme>();
  const classes = useStyles();
  return (
    <MUIBreadcrumbs classes={{ root: variant === 'list' ? classes.breadcrumbsList : classes.breadcrumbsObject }}>
      {elements.map((element) => {
        if (element.current) {
          return (
            <Typography key={element.label} color="text.primary">{element.label}</Typography>
          );
        }
        if (!element.link) {
          return (
            <Typography key={element.label} color="inherit">{element.label}</Typography>
          );
        }
        return (
          <Link key={element.label} to={element.link} style={{ color: theme.palette.text.secondary }}>{element.label}</Link>
        );
      })}
    </MUIBreadcrumbs>
  );
};

export default Breadcrumps;
