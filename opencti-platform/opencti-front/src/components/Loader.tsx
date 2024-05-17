import React, { FunctionComponent, useContext } from 'react';
import CircularProgress from '@mui/material/CircularProgress';
import makeStyles from '@mui/styles/makeStyles';
import { FiligranLoader } from 'filigran-icon';
import { isNotEmptyField } from '../utils/utils';
import { UserContext } from '../utils/hooks/useAuth';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  container: {
    width: '100%',
    minWidth: '100%',
    height: '100%',
    minHeight: 'calc(100vh - 180px)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
  },
  containerInElement: {
    width: '100%',
    height: '100%',
    display: 'table',
  },
  loader: {
    width: '5rem',
    zIndex: 20,
  },
  loaderInElement: {
    width: '5rem',
    margin: 0,
    padding: 0,
    display: 'table-cell',
    verticalAlign: 'middle',
    textAlign: 'center',
  },
  loaderCircle: {
    width: '5rem',
    display: 'inline-block',
  },
}));

export enum LoaderVariant {
  container = 'container',
  inElement = 'inElement',
}

interface LoaderProps {
  variant?: LoaderVariant;
  withRightPadding?: boolean;
  withTopMargin?: boolean;
}

const Loader: FunctionComponent<LoaderProps> = ({
  variant = LoaderVariant.container,
  withRightPadding = false,
  withTopMargin = false,
}) => {
  const classes = useStyles();

  const { settings } = useContext(UserContext);
  const hasFiligranLoader = isNotEmptyField(settings?.enterprise_edition) || !settings?.platform_whitemark;
  return (
    <div
      className={variant === 'inElement' ? classes.containerInElement : classes.container}
      style={
        variant === 'inElement'
          ? {
            paddingRight: withRightPadding ? 200 : 0,
            marginTop: withTopMargin ? 200 : 0,
          }
          : {}
      }
    >
      <div
        className={
          variant === 'inElement' ? classes.loaderInElement : classes.loader
        }
        style={
          variant !== 'inElement'
            ? { paddingRight: withRightPadding ? 100 : 0 }
            : {}
        }
      >
        {hasFiligranLoader ? (
          <FiligranLoader height={variant === 'inElement' ? 40 : 80} />
        ) : (
          <CircularProgress
            size={variant === 'inElement' ? 40 : 80}
            thickness={1}
            className={classes.loaderCircle}
          />
        )}
      </div>
    </div>
  );
};

export default Loader;
