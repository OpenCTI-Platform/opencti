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

export interface PlaybookUpdateAction {
  op?: string;
  attribute?: string;
  value?: {
    label?: string;
    value?: string;
    patch_value?: string | {
      kill_chain_name: string;
      phase_name: string;
    };
  }[];
}

export interface PlaybookUpdateActionsForm {
  actions?: PlaybookUpdateAction[];
  actionsFormValues?: PlaybookUpdateAction['value'][];
}

export const attributesMultiple = [
  'objectMarking',
  'objectLabel',
  'objectAssignee',
  'objectParticipant',
  'killChainPhases',
  'indicator_types',
  'x_mitre_platforms',
];
