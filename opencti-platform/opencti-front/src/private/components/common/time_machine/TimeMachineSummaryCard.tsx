import React from 'react';
import { Text } from '@filigran/design-system';
import { Stack } from '@mui/material';
import Card from '@common/card/Card';

interface TimeMachineSummaryCardProps {
  label: string;
  value: string | number;
}

const TimeMachineSummaryCard = ({ label, value }: TimeMachineSummaryCardProps) => {
  return (
    <Card sx={{ paddingY: 2 }}>
      <Stack height="100%" justifyContent="space-between" gap={1}>
        <Text variant="content-compact" style={{ color: 'var(--text-default-secondary)' }}>{label}</Text>
        <Text variant="title-xl" as="p">{value}</Text>
      </Stack>
    </Card>
  );
};

export default TimeMachineSummaryCard;
