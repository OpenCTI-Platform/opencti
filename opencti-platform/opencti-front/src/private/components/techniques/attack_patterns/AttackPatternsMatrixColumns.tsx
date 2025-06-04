import React, { useEffect, useMemo, useState } from 'react';
import { AccordionActions, AccordionDetails, Badge, Box, Button, ListItemIcon, ListItemText, Menu, MenuItem, Tooltip, Typography } from '@mui/material';
import { AddCircleOutlineOutlined, CheckOutlined, CloseOutlined, ExpandMore, InfoOutlined } from '@mui/icons-material';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import { Link } from 'react-router-dom';
import { useTheme } from '@mui/material/styles';
import { AttackPatternsMatrixProps, attackPatternsMatrixQuery } from '@components/techniques/attack_patterns/AttackPatternsMatrix';
import { AttackPatternsMatrixColumns_data$data, AttackPatternsMatrixColumns_data$key } from './__generated__/AttackPatternsMatrixColumns_data.graphql';
import { AttackPatternsMatrixQuery } from './__generated__/AttackPatternsMatrixQuery.graphql';
import { truncate } from '../../../../utils/String';
import { MESSAGING$ } from '../../../../relay/environment';
import { UserContext } from '../../../../utils/hooks/useAuth';
import type { Theme } from '../../../../components/Theme';
import { hexToRGB } from '../../../../utils/Colors';
import { Accordion, AccordionSummary } from '../../../../components/Accordion';
import { useFormatter } from '../../../../components/i18n';
import useHelper from '../../../../utils/hooks/useHelper';

type AttackPattern = NonNullable<NonNullable<NonNullable<AttackPatternsMatrixColumns_data$data['attackPatternsMatrix']>['attackPatternsOfPhases']>[number]['attackPatterns']>[number];

type AttackPatternElement = AttackPattern & {
  id: AttackPattern['attack_pattern_id'],
  entity_type: string,
  level: number
};

interface AttackPatternsMatrixColumnsProps extends AttackPatternsMatrixProps {
  queryRef: PreloadedQuery<AttackPatternsMatrixQuery>;
}

const LAYOUT_SIZE = {
  BASE_HEIGHT: 310,
  BASE_WIDTH: 110, // Base width when nav is closed
  NAV_WIDTH: 125, // Left nav width
  MARGIN_RIGHT_WIDTH: 195, // Right nav width
};

const COLORS = {
  DEFAULT_BG: 'transparent',
  DEFAULT_BG_HOVER: '#ffffff',
  HIGHLIGHT: '#b71c1c',
  HIGHLIGHT_HOVER: '#d32f2f',
  BADGE: '#fa5e5e',
};

export const attackPatternsMatrixColumnsFragment = graphql`
  fragment AttackPatternsMatrixColumns_data on Query {
    attackPatternsMatrix {
      attackPatternsOfPhases {
        kill_chain_id
        kill_chain_name
        phase_name
        x_opencti_order
        attackPatterns {
          attack_pattern_id
          name
          description
          x_mitre_id
          subAttackPatterns {
            attack_pattern_id
            name
            description
          }
          subAttackPatternsIds
          subAttackPatternsSearchText
          killChainPhasesIds
        }
      }
    }
  }
`;

const AttackPatternsMatrixColumns = ({
  queryRef,
  attackPatterns,
  attackPatternIdsToOverlap,
  marginRight = false,
  searchTerm = '',
  handleAdd,
  selectedKillChain,
  isModeOnlyActive,
}: AttackPatternsMatrixColumnsProps) => {
  const theme = useTheme<Theme>();
  const { isFeatureEnable } = useHelper();
  const isSecurityPlatformEnabled = isFeatureEnable('SECURITY_PLATFORM');
  const { t_i18n } = useFormatter();
  const [hover, setHover] = useState<Record<string, boolean>>({});
  const [anchorEl, setAnchorEl] = useState<EventTarget & Element | null>(null);
  const [selectedAttackPattern, setSelectedAttackPattern] = useState<AttackPatternElement | null>(null);
  const [navOpen, setNavOpen] = useState(localStorage.getItem('navOpen') === 'true');

  const data = usePreloadedQuery<AttackPatternsMatrixQuery>(attackPatternsMatrixQuery, queryRef);
  const { attackPatternsMatrix } = useFragment<AttackPatternsMatrixColumns_data$key>(
    attackPatternsMatrixColumnsFragment,
    data,
  );

  const handleOpen = (element: AttackPatternElement, event: React.MouseEvent) => {
    setAnchorEl(event.currentTarget);
    setSelectedAttackPattern(element);
  };

  const handleClose = () => {
    setAnchorEl(null);
    setSelectedAttackPattern(null);
  };

  const handleAddAttackPattern = (element: AttackPatternElement) => {
    const { id, name, entity_type } = element;

    handleAdd({ id, entity_type, name });
    handleClose();
  };

  const handleToggleHover = (id: string) => {
    setHover((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  useEffect(() => {
    const subscription = MESSAGING$.toggleNav.subscribe({
      next: () => setNavOpen(localStorage.getItem('navOpen') === 'true'),
    });
    return () => subscription.unsubscribe();
  }, []);

  const getLevel = (ap: AttackPattern): number => {
    return attackPatterns.filter((n) => n.id === ap.attack_pattern_id || (ap.subAttackPatternsIds?.includes(n.id))).length;
  };

  const filteredData = useMemo(() => attackPatternsMatrix?.attackPatternsOfPhases
    ?.filter((a) => a.kill_chain_name === selectedKillChain)
    .sort((a, b) => a.x_opencti_order - b.x_opencti_order)
    .map((a) => ({
      ...a,
      attackPatterns: a.attackPatterns
        ?.filter((ap) => !searchTerm
        || ap.name.toLowerCase().includes(searchTerm.toLowerCase())
        || ap.description?.toLowerCase().includes(searchTerm.toLowerCase())
        || ap.x_mitre_id?.toLowerCase().includes(searchTerm.toLowerCase())
        || ap.subAttackPatternsSearchText?.toLowerCase().includes(searchTerm.toLowerCase()))
        .map((ap) => ({
          ...ap,
          id: ap.attack_pattern_id,
          entity_type: 'Attack-Pattern',
          isOverlapping: attackPatternIdsToOverlap?.includes(ap.attack_pattern_id),
          level: getLevel(ap),
          subAttackPatternsTotal: ap.subAttackPatternsIds?.length,
        }))
        .filter((o) => (isModeOnlyActive ? o.level > 0 : o.level >= 0))
        .sort((f, s) => f.name.localeCompare(s.name)),
    })), [attackPatternsMatrix, searchTerm, attackPatterns, attackPatternIdsToOverlap, isModeOnlyActive]);

  const matrixWidth = useMemo(() => {
    const baseOffset = LAYOUT_SIZE.BASE_WIDTH + (navOpen ? LAYOUT_SIZE.NAV_WIDTH : 0);
    const rightOffset = marginRight ? LAYOUT_SIZE.MARGIN_RIGHT_WIDTH : 0;
    return baseOffset + rightOffset;
  }, [marginRight, navOpen]);

  const getBoxStyles = (hasLevel: boolean, isHovered: boolean) => {
    if (hasLevel) {
      const highlightedColor = isHovered ? COLORS.HIGHLIGHT_HOVER : COLORS.HIGHLIGHT;
      return {
        borderColor: highlightedColor,
        backgroundColor: hexToRGB(highlightedColor, 0.2),
      };
    }
    return {
      borderColor: theme.palette.background.accent,
      backgroundColor: isHovered
        ? hexToRGB(COLORS.DEFAULT_BG_HOVER, 0.1)
        : COLORS.DEFAULT_BG,
    };
  };

  return (
    <UserContext.Consumer>
      {({ bannerSettings }) => {
        const matrixHeight = LAYOUT_SIZE.BASE_HEIGHT + (bannerSettings?.bannerHeightNumber || 0) * 2;

        return (
          <Box
            sx={{
              display: 'flex',
              flexDirection: 'column',
              width: `calc(100vw - ${matrixWidth}px)`,
              height: `calc(100vh - ${matrixHeight}px)`,
              overflowX: 'auto',
              whiteSpace: 'nowrap',
              paddingBottom: 2,
              position: 'relative',
              marginBlockStart: 3,
            }}
          >
            <Box display="flex">
              {filteredData?.map((col) => (
                <Box key={col.kill_chain_id} sx={{ mr: 1.5, display: 'flex', flexDirection: 'column', minWidth: 150 }}>
                  <Box sx={{ textAlign: 'center', mb: 1, textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    <Typography sx={{ fontSize: 15, fontWeight: 600 }}>{truncate(col.phase_name, 18)}</Typography>
                    <Typography variant="caption">{`${col.attackPatterns?.length} techniques`}</Typography>
                  </Box>
                  {col.attackPatterns?.map((ap) => {
                    const isHovered = hover[ap.id];
                    const hasLevel = ap.level > 0;
                    return (
                      ap.subAttackPatterns?.length ? (
                        <Accordion
                          id={ap.id}
                          key={ap.id}
                          onMouseEnter={() => handleToggleHover(ap.id)}
                          onMouseLeave={() => handleToggleHover(ap.id)}
                          sx={{
                            border: `1px solid ${colorArray[level][0]}`,
                            borderRadius: 0,
                            backgroundColor: colorArray[level][position],
                          }}
                        >
                          <AccordionSummary
                            expandIcon={<ExpandMore />}
                            sx={{ bgcolor: 'inherit' }}
                          >
                            <Typography variant="body2" fontSize={10}>
                              {ap.name}
                            </Typography>
                          </AccordionSummary>
                          <AccordionDetails
                            sx={{
                              padding: `0 0 0 ${theme.spacing(2)}`,
                              borderTop: `1px solid ${colorArray[level][0]}`,
                              // backgroundColor: colorArray[level][position + 1],
                            }}
                          >
                            {ap.subAttackPatterns.map((subAttackPattern) => {
                              const isSubHovered = hover[subAttackPattern.attack_pattern_id];
                              const subLevel = isSubHovered && ap.level !== 0 ? ap.level - 1 : ap.level;
                              const subPosition = isSubHovered && subLevel === 0 ? 2 : 1;
                              const subColorArray = colors(theme.palette.background.accent);
                              return (
                                <Box
                                  key={subAttackPattern.attack_pattern_id}
                                  onMouseEnter={() => handleToggleHover(subAttackPattern.attack_pattern_id)}
                                  onMouseLeave={() => handleToggleHover(subAttackPattern.attack_pattern_id)}
                                  onClick={(e) => handleOpen(ap, e)}
                                  sx={{
                                    cursor: 'pointer',
                                    border: `1px solid ${subColorArray[subLevel][0]}`,
                                    backgroundColor: subColorArray[subLevel][subPosition],
                                    padding: 1.25,
                                  }}
                                >
                                  <Typography variant="body2" fontSize={10}>
                                    {subAttackPattern.name}
                                  </Typography>
                                </Box>
                              );
                            })}
                          </AccordionDetails>
                          <AccordionActions>
                            <Button
                              startIcon={<InfoOutlined fontSize="small" />}
                              href={`/dashboard/techniques/attack_patterns/${ap.id}`}
                              target="_blank"
                            >
                              View
                            </Button>
                            <Button
                              startIcon={<AddCircleOutlineOutlined fontSize="small" />}
                              onClick={() => handleAddAttackPattern(ap)}
                            >
                              Add
                            </Button>
                          </AccordionActions>
                        </Accordion>
                      ) : (
                        <Badge
                          key={ap.id}
                          invisible={!ap.level}
                          badgeContent={!ap.subAttackPatternsTotal ? ap.level : `${ap.level}/${ap.subAttackPatternsTotal}`}
                          overlap="rectangular"
                          anchorOrigin={{
                            vertical: 'top',
                            horizontal: 'right',
                          }}
                          sx={{
                            '& .MuiBadge-badge': {
                              backgroundColor: COLORS.BADGE,
                              color: theme.palette.common.black,
                              height: '14px',
                              minWidth: '14px',
                              fontSize: '10px',
                              paddingInline: '4px',
                            },
                          }}
                        >
                          <Box
                            onMouseEnter={() => handleToggleHover(ap.id)}
                            onMouseLeave={() => handleToggleHover(ap.id)}
                            onClick={(e) => handleOpen(ap, e)}
                            sx={{
                              display: 'flex',
                              cursor: 'pointer',
                              borderWidth: '1px',
                              borderStyle: 'solid',
                              ...getBoxStyles(hasLevel, isHovered),
                              padding: 1.25,
                              justifyContent: 'space-between',
                              gap: 1,
                              alignItems: 'center',
                              whiteSpace: 'normal',
                              width: '100%',
                            }}
                          >
                            <Typography variant="body2" fontSize={10}>
                              {ap.name}
                            </Typography>
                            {isSecurityPlatformEnabled && attackPatternIdsToOverlap?.length !== undefined && ap.level > 0 && (
                              <Tooltip
                                title={t_i18n('Should cover')}
                                sx={{
                                  display: 'flex',
                                  alignItems: 'center',
                                  height: 19,
                                }}
                              >
                                {ap.isOverlapping
                                  ? <CheckOutlined fontSize="medium" color="success"/>
                                  : <CloseOutlined fontSize="medium" color="error"/>
                                }
                              </Tooltip>
                            )}
                          </Box>
                        </Badge>
                      )
                    );
                  })}
                </Box>
              ))}
            </Box>

            <Menu anchorEl={anchorEl} open={!!anchorEl} onClose={handleClose}>
              {selectedAttackPattern && (
                <>
                  <MenuItem
                    component={Link}
                    to={`/dashboard/techniques/attack_patterns/${selectedAttackPattern?.id}`}
                    target="_blank"
                  >
                    <ListItemIcon><InfoOutlined fontSize="small"/></ListItemIcon>
                    <ListItemText>View</ListItemText>
                  </MenuItem>
                  <MenuItem onClick={() => handleAddAttackPattern(selectedAttackPattern)}>
                    <ListItemIcon><AddCircleOutlineOutlined fontSize="small"/></ListItemIcon>
                    <ListItemText>Add</ListItemText>
                  </MenuItem>
                </>
              )}
            </Menu>
          </Box>
        );
      }}
    </UserContext.Consumer>
  );
};

export default AttackPatternsMatrixColumns;
