import React from 'react';
import * as PropTypes from 'prop-types';
import { createFragmentContainer, graphql } from 'react-relay';
import List from '@mui/material/List';
import Grid from '@mui/material/Grid';
import Card from '@common/card/Card';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import { useFormatter } from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import AttackPatternParentAttackPatterns from './AttackPatternParentAttackPatterns';
import AttackPatternSubAttackPatterns from './AttackPatternSubAttackPatterns';
import AttackPatternCoursesOfAction from './AttackPatternCoursesOfAction';
import AttackPatternDataComponents from './AttackPatternDataComponents';
import StixCoreObjectKillChainPhasesView from '../../common/stix_core_objects/StixCoreObjectKillChainPhasesView';
import Label from '../../../../components/common/label/Label';
import Tag from '@common/tag/Tag';
import TextList from '@common/text/TextList';

const AttackPatternDetailsComponent = (props) => {
  const { t_i18n } = useFormatter();
  const { attackPattern } = props;
  return (
    <div style={{ height: '100%' }}>
      <Card title={t_i18n('Details')}>
        <Grid container={true} spacing={2}>
          <Grid item xs={12}>
            <Label>
              {t_i18n('Description')}
            </Label>
            <ExpandableMarkdown
              source={attackPattern.description}
              limit={300}
            />
          </Grid>
          <Grid item xs={6}>
            {attackPattern.isSubAttackPattern && (
              <AttackPatternParentAttackPatterns
                attackPattern={attackPattern}
              />
            )}
            <Label
              sx={{ marginTop: attackPattern.isSubAttackPattern ? 2 : 0 }}
            >
              {t_i18n('External ID')}
            </Label>
            <FieldOrEmpty source={attackPattern.x_mitre_id}>
              <Tag
                label={attackPattern.x_mitre_id}
              />
            </FieldOrEmpty>
            <div>
              <Label
                sx={{ marginTop: 2 }}
              >
                {t_i18n('Platforms')}
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
              {t_i18n('Detection')}
            </Label>
            <ExpandableMarkdown
              source={attackPattern.x_mitre_detection}
              limit={400}
            />
            <Label
              sx={{ marginTop: 2 }}
            >
              {t_i18n('Required permissions')}
            </Label>
            <TextList list={attackPattern.x_mitre_permissions_required} />
            <AttackPatternCoursesOfAction attackPattern={attackPattern} />
            <AttackPatternDataComponents attackPattern={attackPattern} />
          </Grid>
        </Grid>
      </Card>
    </div>
  );
};

AttackPatternDetailsComponent.propTypes = {
  attackPattern: PropTypes.object,
  classes: PropTypes.object,
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

export default AttackPatternDetails;
