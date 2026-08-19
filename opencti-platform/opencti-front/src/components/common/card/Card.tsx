import { PropsWithChildren, ReactNode } from 'react';
import { useTheme } from '@mui/styles';
import { Stack, SxProps, Card as CardMui, CardActionArea, StackProps } from '@mui/material';
import CardTitle from './CardTitle';
import { Theme } from '../../Theme';
import { Link } from 'react-router-dom';

export interface CardProps extends PropsWithChildren {
  title?: ReactNode;
  action?: ReactNode;
  padding?: 'none' | 'small' | 'medium' | 'horizontal' | 'default';
  sx?: SxProps;
  titleSx?: SxProps;
  titleAlignItems?: StackProps['alignItems'];
  fullHeight?: boolean;
  onClick?: () => void;
  to?: string;
  variant?: 'elevation' | 'outlined';
  disabled?: boolean;
  'aria-label'?: string;
}

const Card = ({
  title,
  children,
  action,
  padding = 'default',
  sx = {},
  titleSx,
  titleAlignItems,
  fullHeight = true,
  onClick,
  to,
  disabled,
  variant,
  ...otherProps
}: CardProps) => {
  const theme = useTheme<Theme>();
  // If no link and no onClick callback then we put the padding on the
  // card container directly, otherwise we put the padding on the
  // CardActionArea component.
  const applyStyleToContainer = !onClick && !to;

  let paddingStyle: SxProps = {
    padding: theme.spacing(3),
  };
  if (padding === 'horizontal') {
    paddingStyle = {
      paddingX: theme.spacing(3),
      paddingY: theme.spacing(1),
    };
  } else if (padding === 'small') {
    paddingStyle = {
      padding: theme.spacing(1),
    };
  } else if (padding === 'medium') {
    paddingStyle = {
      paddingX: theme.spacing(3),
      paddingY: theme.spacing(2),
    };
  } else if (padding === 'none') {
    paddingStyle = {
      padding: 0,
    };
  }

  /**
   * ELEVATION LAYER 1, in every theme.
   *
   * The value read is the LIBRARY'S OWN per-layer hook,
   * `--bg-elevation-default-layer-1`, not MUI's `background.paper`. Both carry
   * the same colour today, so this changes no pixel — but they are two
   * different levers: overriding the hook must move cards and library panels
   * together, which is what a host redeclaring a layer is entitled to expect.
   *
   * Fixed HERE, in the wrapper, deliberately — not in the theme. Repointing
   * `background.secondary` itself would move its EIGHT other consumer lines,
   * in seven files: the platform search input (`SearchInput.jsx:100`), the two
   * date pickers, the drawer header, the saved-filters autocomplete, the
   * relationship-creation header, and the chatbot (two lines). They are inputs
   * and chrome, not card surfaces, and were never part of this question. Same
   * shape as the login-page correction: at the site that paints, not on the
   * shared field.
   */
  const backgroundColor = 'var(--bg-elevation-default-layer-1)';

  const containerSx: SxProps = {
    position: 'relative',
    flexGrow: fullHeight ? 1 : 0,
    borderRadius: theme.spacing(0.5),
    background: variant !== 'outlined'
      ? backgroundColor
      : 'transparent',
    /**
     * The card's own edge, taken from the design system's token rather than
     * from MUI's built-in `divider` default — which is what an `outlined`
     * MUI Card would otherwise draw, and which the product never declares.
     *
     * Read from the PER-LAYER hook, not from the semantic alias. The alias
     * `--border-elevation-subtle-soft` resolves from layer 0 — the one variable
     * `useFdsThemeScope` does not push — so reading the alias leaves the card
     * edge behind on a customer theme while every library `Paper` moves. Same
     * rule as the surface, same assumed consequence: on a customised theme the
     * edge becomes invisible because it coincides with the surface, and on the
     * shipped themes nothing changes.
     *
     * Deliberately ONE LINE here rather than swapping `CardMui` for the
     * library `Paper`. The surface colour and the radius already match the
     * library (see `backgroundColor` above; radius is 4px on both sides), so
     * an exchange would buy this border and nothing else — while forcing the
     * **44** `sx` call sites onto `style`, giving the **13**
     * `variant="outlined"` sites a background they do not have, dropping the
     * asymmetric padding of 11 sites plus part of the 126 dashboard tiles, and
     * leaving a hybrid wrapper the real Card migration would have to undo. Same
     * rendering, none of the debt. Both counts come from
     * `fds-migration/scripts/count-surfaces.mjs`.
     */
    border: '1px solid var(--border-elevation-subtle-soft-layer-1-transparency-15)',
    ...(applyStyleToContainer ? paddingStyle : {}),
    ...(applyStyleToContainer ? sx : {}),
  };

  const actionAreaSx: SxProps = {
    height: '100%',
    ...paddingStyle,
    ...sx,
  };

  let content = children;
  if (onClick || to) {
    let linkProps = {};
    if (to) {
      linkProps = {
        to,
        component: Link,
      };
    }
    content = (
      <CardActionArea
        disabled={disabled}
        onClick={onClick}
        sx={actionAreaSx}
        {...linkProps}
      >
        {children}
      </CardActionArea>
    );
  }

  return (
    <Stack sx={{ height: '100%' }}>
      {(title || action) && (
        <CardTitle
          action={action}
          sx={titleSx}
          alignItems={titleAlignItems}
        >
          {title}
        </CardTitle>
      )}
      <CardMui
        elevation={0}
        sx={containerSx}
        variant={variant}
        {...otherProps}
      >
        {content}
      </CardMui>
    </Stack>
  );
};

export default Card;
