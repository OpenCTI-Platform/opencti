declare module 'use-analytics' {
  import type { ComponentType, Context, FC, ReactNode } from 'react';
  import type { AnalyticsInstance } from 'analytics';

  export function withAnalytics<P extends object>(Component: ComponentType<P>): FC<P>;

  export function useAnalytics(): AnalyticsInstance;

  export function useTrack(): AnalyticsInstance['track'];

  export function usePage(): AnalyticsInstance['page'];

  export function useIdentify(): AnalyticsInstance['identify'];

  export const AnalyticsConsumer: Context<AnalyticsInstance>['Consumer'];
  export const AnalyticsContext: Context<AnalyticsInstance>;

  export function AnalyticsProvider(props: {
    instance: AnalyticsInstance;
    children: ReactNode;
  }): JSX.Element;
}

declare module '@analytics/google-analytics' ;
