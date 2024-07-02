import React, { FunctionComponent, useState } from 'react';
import { Link } from 'react-router-dom';
import * as R from 'ramda';
import { uniq } from 'ramda';
import IconButton from '@mui/material/IconButton';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import Collapse from '@mui/material/Collapse';
import { Launch, LockPattern, ProgressWrench } from 'mdi-material-ui';
import { ExpandLess, ExpandMore } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import {
  StixDomainObjectAttackPatternsKillChainContainer_data$data,
} from '@components/common/stix_domain_objects/__generated__/StixDomainObjectAttackPatternsKillChainContainer_data.graphql';
import { StixDomainObjectAttackPatternsKillChainQuery$variables } from '@components/common/stix_domain_objects/__generated__/StixDomainObjectAttackPatternsKillChainQuery.graphql';
import { Theme } from '@mui/material/styles/createTheme';
import { ListItemButton } from '@mui/material';
import StixCoreRelationshipPopover from '../stix_core_relationships/StixCoreRelationshipPopover';
import ItemMarkings from '../../../../components/ItemMarkings';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';
import { useFormatter } from '../../../../components/i18n';

const useStyles = makeStyles<Theme>((theme) => ({
  container: {
    paddingBottom: 70,
  },
  nested: {
    paddingLeft: theme.spacing(4),
  },
  nested2: {
    paddingLeft: theme.spacing(8),
  },
}));

interface StixDomainObjectAttackPatternsKillChainLinesProps {
  data: StixDomainObjectAttackPatternsKillChainContainer_data$data;
  paginationOptions: StixDomainObjectAttackPatternsKillChainQuery$variables;
  onDelete: () => void;
  searchTerm: string;
  coursesOfAction?: boolean;
}

const StixDomainObjectAttackPatternsKillChainLines: FunctionComponent<StixDomainObjectAttackPatternsKillChainLinesProps> = ({
  data,
  paginationOptions,
  onDelete,
  searchTerm,
  coursesOfAction,
}) => {
  const [expandedLines, setExpandedLines] = useState<Record<string, boolean>>({});
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const handleToggleLine = (lineKey: string) => {
    setExpandedLines({
      ...expandedLines,
      [lineKey]:
        expandedLines[lineKey] !== undefined
          ? !expandedLines[lineKey]
          : false,
    });
  };

  type AttackPatternNode = NonNullable<StixDomainObjectAttackPatternsKillChainContainer_data$data['attackPatterns']>['edges'][number]['node'];
  type NonNullableCoursesOfAction = NonNullable<NonNullable<NonNullable<AttackPatternNode['coursesOfAction']>['edges']>[number]>;
  interface FormattedAttackPattern extends AttackPatternNode {
    killChainPhase: NonNullable<AttackPatternNode['killChainPhases']>[number];
    subattackPatterns_text: string;
  }

  // Extract all kill chain phases
  const filterByKeyword = (n: FormattedAttackPattern) => searchTerm === ''
      || n.name.toLowerCase().indexOf(searchTerm.toLowerCase()) !== -1
      || (n.description ?? '')
        .toLowerCase()
        .indexOf(searchTerm.toLowerCase()) !== -1
      || (n.x_mitre_id ?? '')
        .toLowerCase()
        .indexOf(searchTerm.toLowerCase()) !== -1
      || (n.subattackPatterns_text ?? '')
        .toLowerCase()
        .indexOf(searchTerm.toLowerCase()) !== -1;
  const killChainPhases = uniq((data.attackPatterns?.edges ?? [])
    .map((n) => (n.node.killChainPhases && n.node.killChainPhases.length > 0
      ? n.node.killChainPhases[0]
      : { id: 'unknown', phase_name: t_i18n('Unknown'), x_opencti_order: 99 })));
  const killChainPhasesById = R.indexBy(R.prop('id'), killChainPhases);
  const formattedAttackPatterns = (data.attackPatterns?.edges ?? [])
    .map((n) => n.node)
    .map((n) => ({
      ...n,
      killChainPhase: n.killChainPhases && n.killChainPhases.length > 0
        ? n.killChainPhases[0]
        : { id: 'unknown', phase_name: t_i18n('Unknown'), x_opencti_order: 99 },
      subattackPatterns_text: (n.subAttackPatterns?.edges ?? [])
        .map((o) => `${o.node.x_mitre_id} ${o.node.name} ${o.node.description}`)
        .join(' | '),
    }))
    .sort((a, b) => a.name.localeCompare(b.name))
    .filter(filterByKeyword);
  const groupedAttackPatterns = R.groupBy((n) => n.killChainPhase.id, formattedAttackPatterns);
  const finalAttackPatternsElement = R.pipe(
    R.mapObjIndexed((value, key) => R.assoc('attackPatterns', value, killChainPhasesById[key])),
    R.values,
  )(groupedAttackPatterns) as { id: string, phase_name: string, x_opencti_order: number, attackPatterns: AttackPatternNode[] }[];
  const sortedAttackPatternsElement = finalAttackPatternsElement
    .sort((a, b) => (b.x_opencti_order ?? Number.POSITIVE_INFINITY) - (a.x_opencti_order ?? Number.POSITIVE_INFINITY));
  return (
    <div>
      <div className={classes.container} id="container">
        <List id="test">
          {sortedAttackPatternsElement.map((element) => (
            <div key={element.id}>
              <ListItemButton
                divider={true}
                onClick={() => handleToggleLine(element.id)}
              >
                <ListItemIcon>
                  <Launch color="primary" role="img" />
                </ListItemIcon>
                <ListItemText primary={element.phase_name} />
                <ListItemSecondaryAction>
                  <IconButton
                    onClick={() => handleToggleLine(element.id)}
                    aria-haspopup="true"
                    size="large"
                  >
                    {expandedLines[element.id]
                      === false ? (
                        <ExpandMore />
                      ) : (
                        <ExpandLess />
                      )}
                  </IconButton>
                </ListItemSecondaryAction>
              </ListItemButton>
              <Collapse
                in={expandedLines[element.id] !== false}
              >
                <List>
                  {(element.attackPatterns ?? []).map(
                    (attackPattern) => {
                      const link = `/dashboard/techniques/attack_patterns/${attackPattern.id}`;
                      return (
                        <div key={attackPattern.id}>
                          <ListItemButton
                            classes={{ root: classes.nested }}
                            divider={true}
                            dense={true}
                            component={coursesOfAction ? 'ul' : Link}
                            to={coursesOfAction ? undefined : link}
                            onClick={
                                coursesOfAction
                                  ? () => handleToggleLine(attackPattern.id)
                                  : undefined
                              }
                          >
                            <ListItemIcon>
                              <LockPattern color="primary" role="img" />
                            </ListItemIcon>
                            <ListItemText
                              primary={
                                <span>
                                  <strong>
                                    {attackPattern.x_mitre_id}
                                  </strong>{' '}
                                  - {attackPattern.name}
                                </span>
                                }
                              secondary={
                                  attackPattern.description
                                  && attackPattern.description.length > 0 ? (
                                    <MarkdownDisplay
                                      content={attackPattern.description}
                                      remarkGfmPlugin={true}
                                      commonmark={true}
                                    />
                                    ) : (
                                      t_i18n('No description of this usage')
                                    )
                                }
                            />
                            <ItemMarkings
                              variant="inList"
                              markingDefinitions={
                                  attackPattern.objectMarking ?? []
                                }
                              limit={1}
                            />
                            <div className={classes.nested} >
                              <ListItemSecondaryAction>
                                {coursesOfAction ? (
                                  <IconButton
                                    onClick={() => handleToggleLine(attackPattern.id)}
                                    aria-haspopup="true"
                                    size="large"
                                  >
                                    {expandedLines[attackPattern.id] === false ? (
                                      <ExpandMore />
                                    ) : (
                                      <ExpandLess />
                                    )}
                                  </IconButton>
                                ) : (
                                  <StixCoreRelationshipPopover
                                    stixCoreRelationshipId={attackPattern.id}
                                    paginationOptions={paginationOptions}
                                    onDelete={onDelete}
                                  />
                                )}
                              </ListItemSecondaryAction>
                            </div>
                          </ListItemButton>
                          {coursesOfAction && (
                            <Collapse
                              in={expandedLines[attackPattern.id] !== false}
                            >
                              <List>
                                {((attackPattern.coursesOfAction?.edges ?? [])
                                  .filter((n) => !!n) as NonNullableCoursesOfAction[])
                                  .map(
                                    (courseOfActionEdge) => {
                                      const courseOfAction = courseOfActionEdge.node;
                                      const courseOfActionLink = `/dashboard/techniques/courses_of_action/${courseOfAction.id}`;
                                      return (
                                        <ListItem
                                          key={courseOfAction.id}
                                          classes={{ root: classes.nested2 }}
                                          divider={true}
                                          button={true}
                                          dense={true}
                                          component={Link}
                                          to={courseOfActionLink}
                                        >
                                          <ListItemIcon>
                                            <ProgressWrench
                                              color="primary"
                                              role="img"
                                            />
                                          </ListItemIcon>
                                          <ListItemText
                                            primary={courseOfAction.name}
                                            secondary={
                                              courseOfAction.description
                                              && courseOfAction.description
                                                .length > 0 ? (
                                                  <MarkdownDisplay
                                                    content={
                                                    courseOfAction.description
                                                  }
                                                    remarkGfmPlugin={true}
                                                    commonmark={true}
                                                  ></MarkdownDisplay>
                                                ) : (
                                                  t_i18n(
                                                    'No description of this course of action',
                                                  )
                                                )
                                            }
                                          />
                                        </ListItem>
                                      );
                                    },
                                  )}
                              </List>
                            </Collapse>
                          )}
                        </div>
                      );
                    },
                  )}
                </List>
              </Collapse>
            </div>
          ))}
        </List>
      </div>
    </div>
  );
};

export default StixDomainObjectAttackPatternsKillChainLines;
