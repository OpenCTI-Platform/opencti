import React from 'react';
import { render, screen } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import SecurityCoverageInformation from './SecurityCoverageInformation';

describe('SecurityCoverageInformation', () => {
  it('renders Empty coverage when no coverage_information is provided (details variant)', () => {
    render(<SecurityCoverageInformation coverage_information={null} variant="details" />);

    // Text from the details-variant empty state
    expect(screen.getByText(/Empty coverage/i)).toBeInTheDocument();
    expect(screen.getByText(/--%/)).toBeInTheDocument();
  });

  it('renders coverage name and score for details variant', () => {
    const coverage_information = [
      { coverage_name: 'Sigma', coverage_score: 80 },
      { coverage_name: 'EDR', coverage_score: 30 },
    ];

    render(<SecurityCoverageInformation coverage_information={coverage_information} variant="details" />);

    // Coverage names
    expect(screen.getByText('Sigma')).toBeInTheDocument();
    expect(screen.getByText('EDR')).toBeInTheDocument();

    // Scores with percentage
    expect(screen.getByText('80%')).toBeInTheDocument();
    expect(screen.getByText('30%')).toBeInTheDocument();
  });
});