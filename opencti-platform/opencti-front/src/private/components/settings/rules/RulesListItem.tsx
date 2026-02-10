import React, { CSSProperties } from 'react';
import { Grid2 as Grid, Stack } from '@mui/material';
import DangerZoneBlock from '@components/common/danger_zone/DangerZoneBlock';
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
import { RuleTag } from './RulesListItemTag';
import Card from '../../../../components/common/card/Card';
import Label from '../../../../components/common/label/Label';

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
    textAlign: 'center',
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
              <Stack gap={2}>
                <div>
                  <Label>
                    {t_i18n('Description')}
                  </Label>
                  <span>{t_i18n(rule.description)}</span>
                </div>

                <div>
                  <Label>
                    {t_i18n('Status')}
                  </Label>
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
                </div>

                {isEngineEnabled && taskWork && (
                  <RuleListItemProgressBar taskEnable={task.enable ?? false} work={taskWork} />
                )}
              </Stack>
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
                  <span style={{ width: '30px', flexShrink: 0 }}>{t_i18n('IF')}</span>
                  <RuleTag color={step?.source_color} label={step?.source} />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <span>{t_i18n(step?.relation)}</span>
                  </div>
                  <RuleTag color={step?.target_color} label={step?.target} />
                </div>
              ))}
            </div>
            <div style={{ textAlign: 'center' }}>
              <ArrowRightAlt fontSize="large" />
              <br />
              <span style={{ width: '80px' }}>{t_i18n('THEN')}</span>
            </div>
            <div style={{ flex: '1' }}>
              {(rule.display?.then ?? []).map((step, index) => {
                return (
                  <div key={index} style={styleStep}>
                    <RuleTag action label={step?.action} />
                    <RuleTag color={step?.source_color} label={step?.source} />
                    {step?.relation && (
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <span>{t_i18n(step?.relation)}</span>
                      </div>
                    )}
                    {step?.target && <RuleTag color={step?.target_color} label={step?.target} />}
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
