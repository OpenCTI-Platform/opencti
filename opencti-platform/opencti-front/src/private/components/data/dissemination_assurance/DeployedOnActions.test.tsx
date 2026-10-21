import { describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import DeployedOnActions from './DeployedOnActions';

const slotOf = (testId: string) => getComputedStyle(screen.getByTestId(testId).parentElement as HTMLElement).gridColumn;

describe('DeployedOnActions', () => {
  it('should offer both actions on a failed deployment, each in its own slot', () => {
    testRender(<DeployedOnActions id="deployment-1" deploymentStatus="failed" revoked={false} />);
    expect(slotOf('deployment-retry')).toEqual('1');
    expect(slotOf('deployment-remove')).toEqual('2');
  });

  it('should keep the removal in its slot on a live deployment', () => {
    testRender(<DeployedOnActions id="deployment-1" deploymentStatus="active" revoked={false} />);
    expect(screen.queryByTestId('deployment-retry')).toBeNull();
    expect(slotOf('deployment-remove')).toEqual('2');
  });

  it('should only deploy again a removed deployment', () => {
    testRender(<DeployedOnActions id="deployment-1" deploymentStatus="removed" revoked={false} />);
    expect(slotOf('deployment-retry')).toEqual('1');
    expect(screen.queryByTestId('deployment-remove')).toBeNull();
  });

  it('should not withdraw a deployment whose removal is already requested', () => {
    testRender(<DeployedOnActions id="deployment-1" deploymentStatus="failed" revoked />);
    expect(screen.getByTestId('deployment-retry')).toBeDefined();
    expect(screen.queryByTestId('deployment-remove')).toBeNull();
  });
});
