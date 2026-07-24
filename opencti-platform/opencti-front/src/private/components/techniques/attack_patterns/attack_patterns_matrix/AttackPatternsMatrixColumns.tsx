import React, { useEffect, useMemo, useState } from 'react';
import { Box, ListItemIcon, ListItemText, Menu, MenuItem, Typography } from '@mui/material';
import { AddCircleOutlineOutlined, InfoOutlined } from '@mui/icons-material';
import { useTheme } from '@mui/material/styles';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import { Link } from 'react-router-dom';
import { AttackPatternsMatrixProps, attackPatternsMatrixQuery } from '@components/techniques/attack_patterns/attack_patterns_matrix/AttackPatternsMatrix';
import AccordionAttackPattern from '@components/techniques/attack_patterns/attack_patterns_matrix/AttackPatternsMatrixAccordion';
import AttackPatternsMatrixBadge from '@components/techniques/attack_patterns/attack_patterns_matrix/AttackPatternsMatrixBadge';
import AttackPatternsMatrixColumnsElement from '@components/techniques/attack_patterns/attack_patterns_matrix/AttackPatternsMatrixColumsElement';
import { AttackPatternsMatrixQuery } from '@components/techniques/attack_patterns/attack_patterns_matrix/__generated__/AttackPatternsMatrixQuery.graphql';
import {
  AttackPatternsMatrixColumns_data$data,
  AttackPatternsMatrixColumns_data$key,
} from '@components/techniques/attack_patterns/attack_patterns_matrix/__generated__/AttackPatternsMatrixColumns_data.graphql';
import { truncate } from '../../../../../utils/String';
import { MESSAGING$ } from '../../../../../relay/environment';
import { UserContext } from '../../../../../utils/hooks/useAuth';
import useTopBanner from '../../../../../utils/hooks/useTopBanner';
import { hexToRGB } from '../../../../../utils/Colors';
import type { Theme } from '../../../../../components/Theme';
import { containerTypes } from '../../../../../utils/hooks/useAttributes';

export type AttackPatternsOfPhase = NonNullable<NonNullable<AttackPatternsMatrixColumns_data$data['attackPatternsMatrix']>['attackPatternsOfPhases']>[number];
export type AttackPattern = NonNullable<AttackPatternsOfPhase['attackPatterns']>[number];
export type SubAttackPattern = NonNullable<AttackPattern['subAttackPatterns']>[number];
export type MinimalAttackPattern = {
  attack_pattern_id: string;
  name: string;
};
export type FilteredSubAttackPattern = SubAttackPattern & {
  isCovered: boolean;
  isOverlapping?: boolean;
};

export type FilteredAttackPattern = AttackPattern & {
  isCovered: boolean;
  isOverlapping?: boolean;
  subAttackPatternsTotal?: number;
  subAttackPatterns: FilteredSubAttackPattern[] | undefined;
};

type FilteredData = {
  attackPatterns: FilteredAttackPattern[] | undefined;
} & AttackPatternsOfPhase;

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
  HIGHLIGHT_SECURITY_POSTURE: '#1b5e20',
  HIGHLIGHT_SECURITY_POSTURE_HOVER: '#2e7d32',
  BADGE: '#fa5e5e',
  BADGE_SECURITY_POSTURE: '#79ed98',
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
            x_mitre_id
          }
          subAttackPatternsSearchText
          killChainPhasesIds
        }
      }
    }
  }
`;

export const isSubAttackPatternCovered = (attackPattern: FilteredAttackPattern) => {
  return attackPattern.subAttackPatterns?.some((sub: FilteredSubAttackPattern) => sub.isCovered);
};

export const getBoxStyles = ({
  attackPattern,
  isHovered,
  isSecurityPlatform,
  theme,
}: {
  attackPattern: FilteredAttackPattern | FilteredSubAttackPattern;
  isHovered: boolean;
  isSecurityPlatform: boolean;
  theme: Theme;
}) => {
  // Handle colors for Security Platform page
  const highlightColor = isSecurityPlatform
    ? COLORS.HIGHLIGHT_SECURITY_POSTURE
    : COLORS.HIGHLIGHT;
  const highlightHoverColor = isSecurityPlatform
    ? COLORS.HIGHLIGHT_SECURITY_POSTURE_HOVER
    : COLORS.HIGHLIGHT_HOVER;

  // Is directly covered
  if (attackPattern.isCovered) {
    const color = isHovered ? highlightHoverColor : highlightColor;
    return {
      border: `1px solid ${color}`,
      backgroundColor: hexToRGB(color, 0.2),
    };
  }

  // Covered by sub-attack patterns
  if (isSubAttackPatternCovered(attackPattern as FilteredAttackPattern)) {
    const color = isHovered ? highlightHoverColor : highlightColor;
    return {
      border: `1px solid ${color}`,
      backgroundColor: COLORS.DEFAULT_BG,
    };
  }

  return {
    border: `1px solid ${theme.palette.background.accent}`,
    backgroundColor: isHovered
      ? hexToRGB(COLORS.DEFAULT_BG_HOVER, 0.1)
      : COLORS.DEFAULT_BG,
  };
};

const AttackPatternsMatrixColumns = ({
  queryRef,
  attackPatterns,
  attackPatternIdsToOverlap,
  entityType,
  searchTerm = '',
  handleAdd,
  selectedKillChain,
  isModeOnlyActive,
  inPaper,
  fillContainer,
  onlyActiveSubAttackPatterns,
  entityUsageMap,
  coverageOverlayMap,
  isCoverage = false,
  coverageMap,
  entityId,
  heatmapActive = false,
  frequencyMap,
  heatmapScale,
}: AttackPatternsMatrixColumnsProps) => {
  const theme = useTheme<Theme>();
  const [anchorEl, setAnchorEl] = useState<EventTarget & Element | null>(null);
  const [selectedAttackPattern, setSelectedAttackPattern] = useState<MinimalAttackPattern | null>(null);
  const [navOpen, setNavOpen] = useState(localStorage.getItem('navOpen') === 'true');
  const isSecurityPlatform = entityType === 'SecurityPlatform';

  const data = usePreloadedQuery<AttackPatternsMatrixQuery>(attackPatternsMatrixQuery, queryRef);
  const { attackPatternsMatrix } = useFragment<AttackPatternsMatrixColumns_data$key>(
    attackPatternsMatrixColumnsFragment,
    data,
  );

  const handleOpen = (element: MinimalAttackPattern, event: React.MouseEvent) => {
    setAnchorEl(event.currentTarget);
    setSelectedAttackPattern(element);
  };

  const handleClose = () => {
    setAnchorEl(null);
    setSelectedAttackPattern(null);
  };

  const handleAddAttackPattern = (element: MinimalAttackPattern) => {
    const { attack_pattern_id: id, name } = element;
    handleAdd({ id, entity_type: 'Attack-Pattern', name });
    handleClose();
  };

  useEffect(() => {
    const subscription = MESSAGING$.toggleNav.subscribe({
      next: () => setNavOpen(localStorage.getItem('navOpen') === 'true'),
    });
    return () => subscription.unsubscribe();
  }, []);

  const isAttackPatternCovered = (ap: AttackPattern | SubAttackPattern) => {
    return attackPatterns.filter((n) => n.id === ap.attack_pattern_id).length > 0;
  };

  const getAttackPatternLevel = (ap: AttackPattern): number => {
    return attackPatterns.filter((n) => n.id === ap.attack_pattern_id).length;
  };

  const getSubAttackPatternLevel = (sap: SubAttackPattern): number => {
    return attackPatterns.filter((n) => n.id === sap.attack_pattern_id).length;
  };

  // Frequency > 0 for a given attack-pattern id (heatmap mode only).
  const hasFrequency = (id: string): boolean => (frequencyMap?.get(id) ?? 0) > 0;

  const filteredData: FilteredData[] | undefined = useMemo(() => attackPatternsMatrix?.attackPatternsOfPhases
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
          level: getAttackPatternLevel(ap),
          isCovered: isAttackPatternCovered(ap),
          subAttackPatterns: ap.subAttackPatterns?.map((sub) => ({
            ...sub,
            level: getSubAttackPatternLevel(sub),
            isCovered: isAttackPatternCovered(sub),
            isOverlapping: attackPatternIdsToOverlap?.includes(sub.attack_pattern_id),
          })).filter((sub) => {
            // Heatmap mode still respects the "only used techniques" toggle: when
            // it is on, restrict sub-techniques to used ones; when off, show all.
            if (heatmapActive) return isModeOnlyActive ? hasFrequency(sub.attack_pattern_id) : true;
            return onlyActiveSubAttackPatterns ? sub.isCovered : true;
          }),
          isOverlapping: attackPatternIdsToOverlap?.includes(ap.attack_pattern_id),
          subAttackPatternsTotal: ap.subAttackPatterns?.length,
        }))
        .filter((ap) => {
          // Heatmap mode respects the "only used techniques" toggle. When on,
          // keep techniques used directly or with at least one used
          // sub-technique; when off, show the whole matrix (heatmap just
          // colours the used cells).
          if (heatmapActive && isModeOnlyActive) {
            return hasFrequency(ap.attack_pattern_id) || (ap.subAttackPatterns?.length ?? 0) > 0;
          }
          return isModeOnlyActive ? ap.isCovered || isSubAttackPatternCovered(ap) : true;
        })
        // Order techniques by their MITRE id (e.g. T1078 before T1548) so the
        // column matches the ATT&CK matrix. Fall back to the name when a
        // technique has no x_mitre_id.
        .sort((f, s) => (f.x_mitre_id ?? '').localeCompare(s.x_mitre_id ?? '', undefined, { numeric: true })
          || f.name.localeCompare(s.name)),
    })), [attackPatternsMatrix, searchTerm, attackPatterns, attackPatternIdsToOverlap, isModeOnlyActive,
    onlyActiveSubAttackPatterns, heatmapActive, frequencyMap, selectedKillChain]);

  const { height: topBannerHeight } = useTopBanner();

  const matrixWidth = useMemo(() => {
    const baseOffset = LAYOUT_SIZE.BASE_WIDTH + (navOpen ? LAYOUT_SIZE.NAV_WIDTH : 0);
    let rightOffset = !containerTypes.includes(entityType) ? LAYOUT_SIZE.MARGIN_RIGHT_WIDTH : 0;
    if (inPaper) {
      rightOffset = 40;
    }
    return baseOffset + rightOffset;
  }, [entityType, navOpen]);

  return (
    <UserContext.Consumer>
      {({ bannerSettings }) => {
        const matrixHeight = LAYOUT_SIZE.BASE_HEIGHT + (bannerSettings?.bannerHeightNumber || 0) * 2 + topBannerHeight;
        return (
          <Box
            sx={{
              width: fillContainer ? '100%' : `calc(100vw - ${matrixWidth}px)`,
              height: fillContainer ? '100%' : `calc(100vh - ${matrixHeight}px)`,
              overflowX: 'auto',
              whiteSpace: 'nowrap',
              paddingBottom: fillContainer ? 0 : 2,
              position: 'relative',
              marginBlockStart: fillContainer ? 0 : 3,
            }}
          >
            <Box display="inline-flex" id="container">
              {filteredData?.map((col) => (
                <Box key={col.kill_chain_id} sx={{ mr: 1.5, display: 'flex', flexDirection: 'column', minWidth: 150 }}>
                  <Box sx={{ textAlign: 'center', mb: 1, textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    <Typography sx={{ fontSize: 15, fontWeight: 600 }}>{truncate(col.phase_name, 18)}</Typography>
                    <Typography variant="caption">{`${col.attackPatterns?.length} techniques`}</Typography>
                  </Box>
                  {col.attackPatterns?.map((ap) => {
                    return (
                      ap.subAttackPatterns?.length ? (
                        (() => {
                          // Calculate badge color based on coverage
                          let badgeColor = isSecurityPlatform ? COLORS.BADGE_SECURITY_POSTURE : COLORS.BADGE;
                          let badgeTextColor = theme.palette.common.black || '#000000';

                          if (isCoverage && coverageMap) {
                            // Check if parent or any sub-technique is covered
                            const hasAnyCoveredSubTechniques = ap.subAttackPatterns?.some((sub) => (sub as FilteredSubAttackPattern).isCovered);

                            if (ap.isCovered || hasAnyCoveredSubTechniques) {
                              const parentCoverage = ap.isCovered ? coverageMap.get(ap.attack_pattern_id) : null;
                              const subCoverages = ap.subAttackPatterns
                                ?.filter((sub) => (sub as FilteredSubAttackPattern).isCovered)
                                ?.map((sub) => coverageMap.get((sub as FilteredSubAttackPattern).attack_pattern_id))
                                .filter(Boolean)
                                .flat() || [];

                              const allCoverages = [...(parentCoverage || []), ...subCoverages];

                              if (allCoverages.length > 0) {
                                const avgScore = allCoverages.reduce((sum, c) => sum + (c?.coverage_score || 0), 0) / allCoverages.length;
                                // Green to red gradient for badge
                                const red = Math.round(255 * (1 - avgScore / 100));
                                const green = Math.round(255 * (avgScore / 100));
                                badgeColor = `rgb(${red}, ${green}, 0)`;
                                badgeTextColor = theme.palette.common.white || '#ffffff';
                              } else {
                                // No coverage data but covered - use blue
                                badgeColor = theme.palette.primary.main || '#1976d2';
                                badgeTextColor = theme.palette.common.white || '#ffffff';
                              }
                            }
                          }

                          // The security-posture shield and/or coverage donuts sit in the
                          // cell's top-right corner; when present, offset the sub-technique
                          // count badge so they do not overlap.
                          const showOverlap = !isCoverage
                            && attackPatternIdsToOverlap?.length !== undefined
                            && (ap.isCovered || isSubAttackPatternCovered(ap));
                          const hasCoverageCorner = (coverageOverlayMap?.get(ap.attack_pattern_id)?.length ?? 0) > 0;
                          const hasCornerIndicator = showOverlap || hasCoverageCorner;

                          return (
                            <AttackPatternsMatrixBadge
                              key={ap.attack_pattern_id}
                              attackPattern={ap}
                              color={badgeColor}
                              textColor={badgeTextColor}
                              hasCornerIndicator={hasCornerIndicator}
                            >
                              <AccordionAttackPattern
                                attackPattern={ap}
                                handleOpen={handleOpen}
                                attackPatternIdsToOverlap={attackPatternIdsToOverlap}
                                isSecurityPlatform={isSecurityPlatform}
                                isCoverage={isCoverage}
                                coverageMap={coverageMap}
                                entityId={entityId}
                                entityUsageMap={entityUsageMap}
                                coverageOverlayMap={coverageOverlayMap}
                                heatmapActive={heatmapActive}
                                frequencyMap={frequencyMap}
                                heatmapScale={heatmapScale}
                              />
                            </AttackPatternsMatrixBadge>
                          );
                        })()
                      ) : (
                        <AttackPatternsMatrixColumnsElement
                          key={ap.attack_pattern_id}
                          attackPattern={ap}
                          handleOpen={handleOpen}
                          attackPatternIdsToOverlap={attackPatternIdsToOverlap}
                          isSecurityPlatform={isSecurityPlatform}
                          isCoverage={isCoverage}
                          coverageMap={coverageMap}
                          entityId={entityId}
                          entityUsageMap={entityUsageMap}
                          coverageOverlayMap={coverageOverlayMap}
                          heatmapActive={heatmapActive}
                          frequencyMap={frequencyMap}
                          heatmapScale={heatmapScale}
                        />
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
                    to={`/dashboard/techniques/attack_patterns/${selectedAttackPattern?.attack_pattern_id}`}
                    target="_blank"
                  >
                    <ListItemIcon><InfoOutlined fontSize="small" /></ListItemIcon>
                    <ListItemText>View</ListItemText>
                  </MenuItem>
                  <MenuItem onClick={() => handleAddAttackPattern(selectedAttackPattern)}>
                    <ListItemIcon><AddCircleOutlineOutlined fontSize="small" /></ListItemIcon>
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
