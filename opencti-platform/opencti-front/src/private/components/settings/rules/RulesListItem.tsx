import React, { CSSProperties } from 'react';
import { Grid2 as Grid } from '@mui/material';
import DangerZoneBlock from '@components/common/danger_zone/DangerZoneBlock';
import Typography from '@mui/material/Typography';
import FormGroup from '@mui/material/FormGroup';
import FormControlLabel from '@mui/material/FormControlLabel';
import Switch from '@mui/material/Switch';
import { ArrowRightAlt } from '@mui/icons-material';
import { useTheme } from '@mui/material/styles';
import { useFormatter } from '../../../../components/i18n';
import { Rule, Task } from './RulesList';
import useAuth from '../../../../utils/hooks/useAuth';
import RuleListItemProgressBar from './RulesListItemProgressBar';
import type { Theme } from '../../../../components/Theme';
import Tag from './RulesListItemTag';
import Card from '../../../../components/common/card/Card';

interface RulesListItemProps {
  rule: NonNullable<Rule>;
  task: Task;
  toggle: () => void;
}

const RulesListItem = ({ rule, task, toggle }: RulesListItemProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { platformModuleHelpers } = useAuth();
  const isEngineEnabled = platformModuleHelpers.isRuleEngineEnable();

  const ruleStatus = isEngineEnabled && rule.activated ? t_i18n('Enabled') : t_i18n('Disabled');
  const taskWork = task?.work;

  const styleRuleRoot: CSSProperties = {
    display: 'flex',
    flexDirection: 'column',
  };
  const styleRuleTitle: CSSProperties = {
    textWrap: 'nowrap',
    display: 'flex',
    alignItems: 'center',
    margin: 0,
  };
  const styleDefinition: CSSProperties = {
    display: 'flex',
    alignItems: 'center',
    gap: theme.spacing(4),
  };
  const styleStep: CSSProperties = {
    margin: theme.spacing(1),
    height: 50,
    minWidth: 400,
    display: 'flex',
    alignItems: 'center',
    gap: theme.spacing(1),
  };

  return (
    <Grid container spacing={3} sx={{ marginBottom: 3 }}>
      <Grid size={{ xs: 3 }} sx={styleRuleRoot}>
        <DangerZoneBlock
          type="rules"
          displayTitle={false}
          title={t_i18n(rule.name)}
          sx={{ title: styleRuleTitle }}
          component={({ disabled, style, title }) => (
            <Card
              title={title}
              sx={style}
            >
              <Grid container spacing={3}>
                <Grid size={{ xs: 6 }}>
                  <Typography variant="h3">
                    {t_i18n('Description')}
                  </Typography>
                  {t_i18n(rule.description)}
                </Grid>
                <Grid size={{ xs: 6 }}>
                  <Typography variant="h3" gutterBottom>
                    {t_i18n('Status')}
                  </Typography>
                  <FormGroup>
                    <FormControlLabel
                      label={ruleStatus}
                      control={(
                        <Switch
                          color="secondary"
                          disabled={!isEngineEnabled || disabled}
                          checked={isEngineEnabled && rule.activated}
                          onChange={toggle}
                        />
                      )}
                    />
                  </FormGroup>
                </Grid>
                {isEngineEnabled && taskWork && (
                  <Grid size={{ xs: 12 }}>
                    <RuleListItemProgressBar taskEnable={task.enable ?? false} work={taskWork} />
                  </Grid>
                )}
              </Grid>
            </Card>
          )}
        />
      </Grid>
      <Grid size={{ xs: 9 }}>
        <Card title=" ">
          <div style={styleDefinition}>
            <div style={{ flex: '1' }}>
              {(rule.display?.if ?? []).map((step, index) => (
                <div key={index} style={styleStep}>
                  <Tag variant="if">{t_i18n('IF')}</Tag>
                  <Tag color={step?.source_color}>{step?.source}</Tag>
                  <Tag color={step?.identifier_color}>{t_i18n(step?.relation)}</Tag>
                  <Tag color={step?.target_color}>{step?.target}</Tag>
                </div>
              ))}
            </div>
            <div style={{ textAlign: 'center' }}>
              <ArrowRightAlt fontSize="large" />
              <br />
              <Tag variant="then">{t_i18n('THEN')}</Tag>
            </div>
            <div style={{ flex: '1' }}>
              {(rule.display?.then ?? []).map((step, index) => {
                return (
                  <div key={index} style={styleStep}>
                    <Tag variant="action">{step?.action}</Tag>
                    <Tag color={step?.source_color}>{step?.source}</Tag>
                    {step?.relation && <Tag color={step?.identifier_color}>{t_i18n(step?.relation)}</Tag>}
                    {step?.target && <Tag color={step?.target_color}>{step?.target}</Tag>}
                  </div>
                );
              })}
            </div>
          </div>
        </Card>
      </Grid>
    </Grid>
  );
};

export default RulesListItem;
