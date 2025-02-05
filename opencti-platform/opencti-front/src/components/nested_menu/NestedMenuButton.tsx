import * as React from 'react';
import Button from '@mui/material/Button';
import MenuItem from '@mui/material/MenuItem';
import { Box, ClickAwayListener, Grow, MenuList, Paper, Popper, Typography } from '@mui/material';
import ChevronRight from '@mui/icons-material/ChevronRight';
import { ButtonProps } from '@mui/material/Button/Button';

// This function checks whether a point (x, y) is on the left or right side of a line formed by two points (px, py) and (qx, qy).
// If the result is negative, the point is on the right side of the line. If positive, it's on the left side.
// It helps us determine if a point is on the same side as a vertex of the triangle when compared to its edges.
const sign = (
  px: number,
  py: number,
  qx: number,
  qy: number,
  rx: number,
  ry: number,
) => {
  return (px - rx) * (qy - ry) - (qx - rx) * (py - ry);
};

// This function checks if a point (x, y) is inside a triangle formed by three points (x1, y1), (x2, y2), and (x3, y3).
const pointInTriangle = (
  currentMouseCoordinates: Array<number>,
  triangleCoordinates: Array<Array<number>>,
) => {
  const [[x1, y1], [x2, y2], [x3, y3]] = triangleCoordinates;
  const [x, y] = currentMouseCoordinates;

  const b1 = sign(x, y, x1, y1, x2, y2) <= 0;
  const b2 = sign(x, y, x2, y2, x3, y3) <= 0;
  const b3 = sign(x, y, x3, y3, x1, y1) <= 0;
  // If all signs are the same (either all negative or all positive), the point is inside the triangle.
  return b1 === b2 && b2 === b3;
};

type Option = {
  value: string;
  menuLevel: number;
  label?: string; // if not present, value is used
  onClick?: () => void; // individual click handler
  selected?: boolean;
  nestedOptions? : Option[];
};

type NestedMenuProps = {
  menuButtonChildren?: React.ReactNode;
  menuButtonProps?: ButtonProps;
  options: Array<Option>;
  menuLevels: number;
  onClick?: (option: Option) => void; // global click handler
};

const NestedMenuButton: React.FC<NestedMenuProps> = ({
  menuButtonProps = {},
  menuButtonChildren,
  options,
  menuLevels,
  onClick,
}: NestedMenuProps) => {
  const [anchors, setAnchors] = React.useState<{
    elements: Array<null | HTMLElement>;
    options: Array<null | typeof options>;
  }>({
    elements: new Array(menuLevels).fill(null),
    options: new Array(menuLevels).fill(null),
  });

  const mouseEntered = React.useRef<Record<string, boolean>>({});
  const mouseLeftCoordinates = React.useRef<Array<number>>([]);
  const buttonRef = React.useRef(null);
  const mouseIdleTimer = React.useRef<number | null>(null);

  const handleOpen = (
    event: React.MouseEvent<HTMLElement> | React.KeyboardEvent<HTMLElement>,
    level = 0,
    nestedOptions = options,
  ) => {
    const target = event.target as HTMLElement;

    setAnchors((prevAnchors) => ({
      elements: prevAnchors.elements.map((element, index) => (index === level ? target : element)),
      options: prevAnchors.options.map((element, index) => (index === level ? nestedOptions : element)),
    }));
  };

  const handleClose = (level: number) => {
    setAnchors((prevAnchors) => ({
      elements: prevAnchors.elements.map((element, index) => (index >= level ? null : element)),
      options: prevAnchors.options.map((element, index) => (index >= level ? null : element)),
    }));
  };

  const handleClickAway = (event: MouseEvent | TouchEvent) => {
    if (event.target === buttonRef.current) {
      handleClose(0);
      return;
    }

    const optionWithoutSubMenu = anchors.elements.every(
      (element) => !element || !event.composedPath().includes(element),
    );

    if (optionWithoutSubMenu) {
      handleClose(0);
    }
  };

  const handleClickOption = (option: Option) => {
    if (!option.nestedOptions) {
      handleClose(0);
    } else {
      return; // no handler on submenu's parent
    }
    option.onClick?.();
    onClick?.(option);
  };

  const getId = (opt: (typeof options)[0], index: number) => {
    return `${index}-${opt.menuLevel}`;
  };

  const handleMouseMove = (
    event: React.MouseEvent<HTMLLIElement, MouseEvent>,
    option: Option,
    optIndex: number,
  ) => {
    let shouldComputeSubMenuOpenLogic = true;
    const submenu = document.querySelector(`#nested-menu-${option.menuLevel + 1}`);

    const computeSubMenuLogic = () => {
      if (!mouseEntered.current[getId(option, optIndex)]) {
        mouseEntered.current[getId(option, optIndex)] = true;
        // Close all prior submenus if the mouse transitions from an option with a submenu to an option without a submenu.
        if (!option.nestedOptions) {
          handleClose(option.menuLevel + 1);
        } else if (
          // If the mouse moves from an option with a submenu to another option with a submenu, open the submenu of the current option and close the submenu of the previous option.
          option.nestedOptions
          && anchors.options[option.menuLevel + 1]
          && !option.nestedOptions.every(
            (val, i) => val.value === anchors.options[option.menuLevel + 1]?.[i].value,
          )
        ) {
          handleClose(option.menuLevel + 1);
          handleOpen(event, option.menuLevel + 1, option.nestedOptions);
        } else {
          handleOpen(event, option.menuLevel + 1, option.nestedOptions);
        }
      }
    };

    if (mouseLeftCoordinates.current.length > 0 && submenu) {
      const { x, y, height } = submenu.getBoundingClientRect();

      // Form a virtual triangle using the left mouse coordinates and the top-left and bottom-left coordinates of the submenu.
      // If the current mouse coordinates fall within this triangle, skip the submenu logic computation.
      // Check https://twitter.com/diegohaz/status/1283558204178407427 for more context.
      const currentMouseCoordinates = [event.clientX, -event.clientY];
      const virtualTriangleCoordinates = [
        [x, -y],
        [x, -(y + height)],
        [mouseLeftCoordinates.current[0], mouseLeftCoordinates.current[1]],
      ];

      if (pointInTriangle(currentMouseCoordinates, virtualTriangleCoordinates)) {
        shouldComputeSubMenuOpenLogic = false;
        if (mouseIdleTimer.current) {
          clearTimeout(mouseIdleTimer.current);
        }

        // if mouse is inside triangle and yet hasn't moved, we need to compute submenu logic after a delay
        mouseIdleTimer.current = window.setTimeout(() => {
          computeSubMenuLogic();
        }, 50);
      } else {
        shouldComputeSubMenuOpenLogic = true;
      }
    }

    if (shouldComputeSubMenuOpenLogic) {
      if (mouseIdleTimer.current) {
        clearTimeout(mouseIdleTimer.current);
      }
      computeSubMenuLogic();
    }
  };

  const handleMouseLeave = (
    event: React.MouseEvent<HTMLLIElement, MouseEvent>,
    option: Option,
    optIndex: number,
  ) => {
    mouseLeftCoordinates.current = [event.clientX, -event.clientY];

    if (mouseIdleTimer.current) {
      clearTimeout(mouseIdleTimer.current);
    }
    mouseEntered.current[getId(option, optIndex)] = false;
  };

  const handleKeyDown = (
    event: React.KeyboardEvent<HTMLLIElement>,
    option: Option,
  ) => {
    if (option.nestedOptions) {
      if (event.key === 'ArrowRight' || event.key === 'Enter') {
        handleOpen(event, option.menuLevel + 1, option.nestedOptions);
      }
    }
    if (event.key === 'ArrowLeft' && option.menuLevel > 0) {
      handleClose(option.menuLevel);
      anchors.elements[option.menuLevel]?.focus();
    }

    if (event.key === 'Escape') {
      handleClose(0);
    }
  };

  return (
    <React.Fragment>
      <Button
        ref={buttonRef}
        onClick={(event) => {
          handleOpen(event);
        }}
        {...menuButtonProps}
      >
        { menuButtonChildren ?? 'Menu' }
      </Button>

      {anchors.elements.map((anchorElement, index) => (anchorElement ? (
        <Popper
          open={Boolean(anchorElement)}
          anchorEl={anchorElement}
          key={`${anchorElement.innerText} menu`}
          role={undefined}
          placement={index > 0 ? 'right-start' : 'bottom-start'}
          transition
          style={{ zIndex: 9999 }}
        >
          {({ TransitionProps }) => (
            <Grow
              {...(TransitionProps || {})}
              style={{
                transformOrigin: 'left top',
              }}
            >
              <Paper>
                <ClickAwayListener onClickAway={handleClickAway}>
                  <MenuList
                    autoFocusItem={Boolean(anchorElement)}
                    id={`nested-menu-${index}`}
                    aria-labelledby="nested-button"
                  >
                    {(anchors.options[index] ?? []).map((option, optIndex) => (
                      <MenuItem
                        key={option.value}
                        selected={!!option.selected}
                        aria-haspopup={!!(option.nestedOptions ?? undefined)}
                        aria-expanded={
                            option.nestedOptions
                              ? anchors.elements.some(
                                (element) => element?.innerText === option.value,
                              )
                              : undefined
                          }
                        onClick={() => handleClickOption(option)}
                        onMouseMove={(event) => handleMouseMove(event, option, optIndex) }
                        onMouseLeave={(event) => handleMouseLeave(event, option, optIndex) }
                        onKeyDown={(event) => handleKeyDown(event, option)}
                      >
                        <Box
                          sx={{
                            display: 'flex',
                            justifyContent: 'space-between',
                            width: '100%',
                            alignItems: 'center',
                          }}
                        >
                          <Typography>{option.label ?? option.value}</Typography>
                          {option.nestedOptions ? (
                            <ChevronRight fontSize="small" />
                          ) : null}
                        </Box>
                      </MenuItem>
                    ))}
                  </MenuList>
                </ClickAwayListener>
              </Paper>
            </Grow>
          )}
        </Popper>
      ) : null))}
    </React.Fragment>
  );
};

export default NestedMenuButton;
