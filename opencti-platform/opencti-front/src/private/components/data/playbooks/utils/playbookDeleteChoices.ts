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

// What the delete dialog offers for a step:
// - a leaf: a simple confirmation (nothing hangs below it);
// - a step with children: "this step only" (the default, its children stay wired to its parents)
//   or "this step and the N steps after it";
// - the entry point with children: only the whole branch (its children would have no parent).
export type PlaybookDeleteChoice = 'step' | 'branch';

export interface PlaybookDeleteOptions {
  choices: PlaybookDeleteChoice[];
  defaultChoice: PlaybookDeleteChoice;
  // The steps below the step, each counted once (a step reached by two paths is one step).
  descendants: number;
}

interface LinkLike { source: string; target: string }

// The steps reachable from nodeId through the links, nodeId excluded; isStep filters out the
// add buttons of the canvas, which are nodes too.
export const countDescendantSteps = (nodeId: string, links: LinkLike[], isStep: (id: string) => boolean): number => {
  const seen = new Set<string>();
  const queue = [nodeId];
  while (queue.length > 0) {
    const current = queue.shift() as string;
    links.filter((l) => l.source === current).forEach((l) => {
      if (!seen.has(l.target) && l.target !== nodeId) {
        seen.add(l.target);
        queue.push(l.target);
      }
    });
  }
  return [...seen].filter(isStep).length;
};

export const playbookDeleteOptions = (descendants: number, isEntryPoint: boolean): PlaybookDeleteOptions => {
  if (descendants === 0) return { choices: ['step'], defaultChoice: 'step', descendants };
  if (isEntryPoint) return { choices: ['branch'], defaultChoice: 'branch', descendants };
  return { choices: ['step', 'branch'], defaultChoice: 'step', descendants };
};
