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
import Grid from '@mui/material/Grid2';
import Skeleton from '@mui/material/Skeleton';
import Stack from '@mui/material/Stack';
import Card from '@common/card/Card';

/** The shape of an investigation while it loads: the status header, then the goal plan beside the conclusion and the details. */
const InvestigationRunSkeleton = () => (
  <Stack spacing={3} data-testid="investigation-run-skeleton" aria-busy>
    <Card title={<Skeleton variant="text" width={120} />}>
      <Stack spacing={2}>
        <Stack direction="row" spacing={1.5} alignItems="center">
          <Skeleton variant="rounded" width={96} height={24} />
          <Skeleton variant="text" width="40%" />
        </Stack>
        <Skeleton variant="text" width="25%" />
        <Skeleton variant="rounded" height={8} />
      </Stack>
    </Card>
    <Grid container spacing={3}>
      <Grid size={{ xs: 12, lg: 8 }}>
        <Card title={<Skeleton variant="text" width={220} />}>
          <Stack spacing={1.5}>
            {[0, 1, 2, 3].map((key) => (
              <Stack key={key} direction="row" spacing={1.5} alignItems="center">
                <Skeleton variant="circular" width={20} height={20} />
                <Skeleton variant="text" width={`${60 - key * 10}%`} />
              </Stack>
            ))}
          </Stack>
        </Card>
      </Grid>
      <Grid size={{ xs: 12, lg: 4 }}>
        <Stack spacing={3}>
          {[0, 1].map((key) => (
            <Card key={key} title={<Skeleton variant="text" width={100} />}>
              <Stack spacing={1}>
                <Skeleton variant="text" width="80%" />
                <Skeleton variant="text" width="60%" />
              </Stack>
            </Card>
          ))}
        </Stack>
      </Grid>
    </Grid>
  </Stack>
);

export default InvestigationRunSkeleton;
