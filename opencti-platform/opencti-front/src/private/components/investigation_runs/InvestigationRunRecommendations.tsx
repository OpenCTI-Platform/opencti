/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import React from 'react';
import { graphql } from 'react-relay';
import { Link } from 'react-router';
import Box from '@mui/material/Box';
import Divider from '@mui/material/Divider';
import Stack from '@mui/material/Stack';
import Typography from '@mui/material/Typography';
import { AddTaskOutlined, PlaylistAddCheckOutlined } from '@mui/icons-material';
import { Chip } from '@filigran/design-system';
import Card from '@common/card/Card';
import Button from '@common/button/Button';
import { useFormatter } from '../../../components/i18n';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import InvestigationRunFeedback from './InvestigationRunFeedback';
import {
  elementPath,
  feedbackDecisionFor,
  emptySectionSentence,
  PRIORITY_LABELS,
  prioritySeverity,
  RECOMMENDATION_ACTION_LABELS,
  RECOMMENDATION_STATUS_LABELS,
  recommendationStatusSeverity,
  reportMutationOutcome,
  SEVERITY_LABELS,
} from './investigationRunUtils';
import type { InvestigationRunView_run$data } from './__generated__/InvestigationRunView_run.graphql';
import { InvestigationRunRecommendationsApplyMutation } from './__generated__/InvestigationRunRecommendationsApplyMutation.graphql';

const investigationRunRecommendationsApplyMutation = graphql`
  mutation InvestigationRunRecommendationsApplyMutation($id: ID!, $recommendationId: String!, $mode: InvestigationRecommendationApplyMode!) {
    investigationRunRecommendationApply(id: $id, recommendationId: $recommendationId, mode: $mode) {
      id
      ...InvestigationRunView_run
    }
  }
`;

interface InvestigationRunRecommendationsProps {
  run: InvestigationRunView_run$data;
}

const InvestigationRunRecommendations = ({ run }: InvestigationRunRecommendationsProps) => {
  const { t_i18n } = useFormatter();
  const [commitApply, applying] = useApiMutation<InvestigationRunRecommendationsApplyMutation>(investigationRunRecommendationsApplyMutation);
  const apply = (recommendationId: string, mode: 'task' | 'course_of_action') => {
    commitApply({
      variables: { id: run.id, recommendationId, mode },
      onCompleted: (_, errors) => {
        reportMutationOutcome(errors, t_i18n('The recommendation was applied'));
      },
    });
  };
  const { recommendations } = run;
  return (
    <Card
      title={t_i18n('Recommendations')}
      action={recommendations.length > 0 ? (
        <Typography variant="body2" color="text.secondary" data-testid="investigation-recommendations-count">
          {t_i18n('{count, plural, one {# recommendation} other {# recommendations}}', { values: { count: recommendations.length } })}
        </Typography>
      ) : undefined}
    >
      {recommendations.length === 0 ? (
        <Typography variant="body2" color="text.secondary">
          {emptySectionSentence(run, t_i18n, t_i18n('Recommendations are proposed as the investigation concludes.'), t_i18n('No recommendation was proposed.'))}
        </Typography>
      ) : (
        <Stack spacing={2} divider={<Divider flexItem />}>
          {recommendations.map((recommendation) => (
            <Stack
              key={recommendation.id}
              direction={{ xs: 'column', md: 'row' }}
              spacing={2}
              justifyContent="space-between"
              alignItems={{ md: 'center' }}
              data-testid="investigation-recommendation"
            >
              <Stack spacing={0.75} sx={{ flex: 1 }}>
                <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
                  <Chip label={t_i18n(PRIORITY_LABELS[recommendation.priority] ?? 'Medium priority')} severity={prioritySeverity(recommendation.priority)} size="sm" />
                  <Chip label={t_i18n(RECOMMENDATION_ACTION_LABELS[recommendation.action_kind] ?? 'Other')} size="sm" />
                  <Chip
                    label={t_i18n(RECOMMENDATION_STATUS_LABELS[recommendation.status] ?? 'Proposed')}
                    severity={recommendationStatusSeverity(recommendation.status)}
                    size="sm"
                  />
                  {recommendation.severity && (
                    <Chip
                      label={t_i18n('Severity: {severity}', { values: { severity: t_i18n(SEVERITY_LABELS[recommendation.severity] ?? 'Medium') } })}
                      size="sm"
                    />
                  )}
                </Stack>
                <Typography variant="body1">{recommendation.text}</Typography>
                {recommendation.rationale && <Typography variant="body2" color="text.secondary">{recommendation.rationale}</Typography>}
                {recommendation.courseOfAction && (
                  <Typography variant="body2" color="text.secondary">
                    {t_i18n('Course of action: {name}', {
                      values: { name: <Link key="coa" to={elementPath(recommendation.courseOfAction.id)}>{recommendation.courseOfAction.name}</Link> },
                    })}
                  </Typography>
                )}
                {recommendation.task_id && (
                  <Box><Link to={elementPath(recommendation.task_id)}>{t_i18n('Open the task')}</Link></Box>
                )}
              </Stack>
              <Stack direction="row" spacing={1} alignItems="center">
                {recommendation.status === 'proposed' && (
                  <Security needs={[KNOWLEDGE_KNUPDATE]}>
                    <>
                      <Button
                        size="small"
                        variant="secondary"
                        startIcon={<AddTaskOutlined fontSize="small" />}
                        disabled={applying}
                        onClick={() => apply(recommendation.id, 'task')}
                      >
                        {t_i18n('Create task')}
                      </Button>
                      {recommendation.course_of_action_id && (
                        <Button
                          size="small"
                          variant="secondary"
                          startIcon={<PlaylistAddCheckOutlined fontSize="small" />}
                          disabled={applying}
                          onClick={() => apply(recommendation.id, 'course_of_action')}
                        >
                          {t_i18n('Apply course of action')}
                        </Button>
                      )}
                    </>
                  </Security>
                )}
                <InvestigationRunFeedback
                  runId={run.id}
                  itemType="recommendation"
                  itemRef={recommendation.id}
                  itemLabel={recommendation.text}
                  decision={feedbackDecisionFor(run.analyst_feedback, 'recommendation', recommendation.id)}
                />
              </Stack>
            </Stack>
          ))}
        </Stack>
      )}
    </Card>
  );
};

export default InvestigationRunRecommendations;
