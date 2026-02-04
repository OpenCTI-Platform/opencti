import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer, graphql } from 'react-relay';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { PermIdentity } from '@mui/icons-material';
import Grid from '@mui/material/Grid';
import Card from '@common/card/Card';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import inject18n from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import AttackPatternParentAttackPatterns from './AttackPatternParentAttackPatterns';
import AttackPatternSubAttackPatterns from './AttackPatternSubAttackPatterns';
import AttackPatternCoursesOfAction from './AttackPatternCoursesOfAction';
import AttackPatternDataComponents from './AttackPatternDataComponents';
import StixCoreObjectKillChainPhasesView from '../../common/stix_core_objects/StixCoreObjectKillChainPhasesView';
import Label from '../../../../components/common/label/Label';
import Tag from '@common/tag/Tag';
import TextList from '@common/text/TextList';

class AttackPatternDetailsComponent extends Component {
  render() {
    const { t, attackPattern } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Card title={t('Details')}>
          <Grid container={true} spacing={2}>
            <Grid item xs={6}>
              {attackPattern.isSubAttackPattern && (
                <AttackPatternParentAttackPatterns
                  attackPattern={attackPattern}
                />
              )}
              <Label
                sx={{ marginTop: attackPattern.isSubAttackPattern ? 2 : 0 }}
              >
                {t('External ID')}
              </Label>
              <FieldOrEmpty source={attackPattern.x_mitre_id}>
                <Tag
                  label={attackPattern.x_mitre_id}
                />
              </FieldOrEmpty>
              <Label
                sx={{ marginTop: 2 }}
              >
                {t('Description')}
              </Label>
              <ExpandableMarkdown
                source={attackPattern.description}
                limit={300}
              />
              <div>
                <Label
                  sx={{ marginTop: 2 }}
                >
                  {t('Platforms')}
                </Label>
                <List style={{ paddingTop: 0 }}>
                  <TextList list={attackPattern.x_mitre_platforms} />
                </List>
              </div>
              <AttackPatternSubAttackPatterns attackPattern={attackPattern} />
            </Grid>
            <Grid item xs={6}>
              <StixCoreObjectKillChainPhasesView
                killChainPhases={attackPattern.killChainPhases}
                firstLine={true}
              />
              <Label
                sx={{ marginTop: 2 }}
              >
                {t('Detection')}
              </Label>
              <ExpandableMarkdown
                source={attackPattern.x_mitre_detection}
                limit={400}
              />
              <Label
                sx={{ marginTop: 2 }}
              >
                {t('Required permissions')}
              </Label>
              <List style={{ paddingTop: 0 }}>
                <FieldOrEmpty source={attackPattern.x_mitre_permissions_required}>
                  {attackPattern.x_mitre_permissions_required?.map(
                    (permission) => (
                      <ListItem key={permission} dense={true} divider={true}>
                        <ListItemIcon>
                          <PermIdentity />
                        </ListItemIcon>
                        <ListItemText primary={permission} />
                      </ListItem>
                    ),
                  )}
                </FieldOrEmpty>
              </List>
              <AttackPatternCoursesOfAction attackPattern={attackPattern} />
              <AttackPatternDataComponents attackPattern={attackPattern} />
            </Grid>
          </Grid>
        </Card>
      </div>
    );
  }
}

AttackPatternDetailsComponent.propTypes = {
  attackPattern: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const AttackPatternDetails = createFragmentContainer(
  AttackPatternDetailsComponent,
  {
    attackPattern: graphql`
      fragment AttackPatternDetails_attackPattern on AttackPattern {
        id
        description
        x_mitre_platforms
        x_mitre_permissions_required
        x_mitre_id
        x_mitre_detection
        isSubAttackPattern
        killChainPhases {
          id
          entity_type
          kill_chain_name
          phase_name
          x_opencti_order
        }
        objectLabel {
          id
          value
          color
        }
        ...AttackPatternSubAttackPatterns_attackPattern
        ...AttackPatternParentAttackPatterns_attackPattern
        ...AttackPatternCoursesOfAction_attackPattern
        ...AttackPatternDataComponents_attackPattern
      }
    `,
  },
);

export default compose(inject18n)(AttackPatternDetails);
