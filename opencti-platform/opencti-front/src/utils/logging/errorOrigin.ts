import type {
  AppModule as GraphQLAppModule,
  ErrorDependency as GraphQLErrorDependency,
  ErrorOrigin as GraphQLErrorOrigin,
} from './__generated__/GraphQLLogRecordExporterAddLogsMutation.graphql';

// Module-scoped error classification (RFC 0006), from the browser's point of view.
// The enums are the GraphQL ones: the backend accepts no other value.
type Known<T> = Exclude<T, '%future added value'>;
export type AppModule = Known<GraphQLAppModule>;
export type ErrorDependency = Known<GraphQLErrorDependency>;
export type ErrorOrigin = Known<GraphQLErrorOrigin>;

export const APP_MODULE = {
  CORE: 'core',
  CATALOG: 'catalog',
  CONNECTOR: 'connector',
} as const satisfies Record<string, AppModule>;

// region entry module
// The module of the page the user is on: the entry module of every record logged there.
const MODULE_ROUTES: Array<[string, AppModule]> = [
  ['/dashboard/integrations/available', APP_MODULE.CATALOG],
  ['/dashboard/integrations/catalog', APP_MODULE.CATALOG],
  ['/dashboard/integrations/deployed', APP_MODULE.CONNECTOR],
  ['/dashboard/integrations/connectors', APP_MODULE.CONNECTOR],
];

export const resolveRouteModule = (pathname: string): AppModule | undefined => {
  // The platform may be served under a base path: match from `/dashboard` on.
  const dashboardIndex = pathname.indexOf('/dashboard');
  if (dashboardIndex < 0) {
    return undefined;
  }
  const path = pathname.substring(dashboardIndex);
  return MODULE_ROUTES.find(([prefix]) => path === prefix || path.startsWith(`${prefix}/`))?.[1];
};
// endregion

// region origin
// The UI logs what only the browser sees: its own crashes, its static files that fail to load,
// and API requests that never reached the backend. An error the API returned is already logged by
// the backend, with its own classification: from the UI, it is a rejected input or a failing API.
export interface ErrorClassification {
  origin: ErrorOrigin;
  dependency?: ErrorDependency;
}

// A lazy-loaded chunk that is gone, typically after a deployment.
const ASSET_LOAD_FAILURES = [
  /Failed to fetch dynamically imported module/i,
  /error loading dynamically imported module/i,
  /Importing a module script failed/i,
  /Unable to preload CSS/i,
];
// `fetch` rejecting: the request never got a response (Chrome, Firefox, Safari).
const NETWORK_FAILURES = [/^Failed to fetch$/i, /NetworkError when attempting to fetch resource/i, /^Load failed$/i];
// A proxy in front of the platform answering on its behalf.
const PROXY_UNAVAILABLE_STATUSES = [502, 503, 504];

interface ApiResponse {
  status?: number;
  errors?: Array<{ extensions?: { origin?: string } }>;
}

const errorMessage = (error: unknown) => {
  if (error instanceof Error) return error.message;
  return typeof error === 'string' ? error : '';
};

// The response of a failed Relay request, as react-relay-network-modern or the app's wrappers expose it.
const apiResponseOf = (error: unknown): ApiResponse | undefined => {
  const candidate = error as { res?: ApiResponse; data?: { res?: ApiResponse } } | null | undefined;
  return candidate?.res ?? candidate?.data?.res;
};

export const classifyFrontendError = (error: unknown): ErrorClassification => {
  const message = errorMessage(error);
  if (ASSET_LOAD_FAILURES.some((pattern) => pattern.test(message))) {
    return { origin: 'infra', dependency: 'assets' };
  }
  if (error instanceof TypeError && NETWORK_FAILURES.some((pattern) => pattern.test(message))) {
    return { origin: 'infra', dependency: 'api' };
  }
  const response = apiResponseOf(error);
  const apiErrors = response?.errors ?? [];
  if (apiErrors.length > 0) {
    const isRejectedInput = apiErrors.every((apiError) => apiError?.extensions?.origin === 'input');
    return isRejectedInput ? { origin: 'input' } : { origin: 'infra', dependency: 'api' };
  }
  if (response?.status && PROXY_UNAVAILABLE_STATUSES.includes(response.status)) {
    return { origin: 'infra', dependency: 'api' };
  }
  return { origin: 'code' };
};
// endregion

// region guards
// A value outside the GraphQL enums would make the backend reject the whole batch of records.
const APP_MODULES: readonly string[] = Object.values(APP_MODULE);
const ERROR_ORIGINS: readonly string[] = ['code', 'infra', 'input'] satisfies ErrorOrigin[];
const ERROR_DEPENDENCIES: readonly string[] = ['elasticsearch', 'rabbitmq', 'redis', 's3', 'remote_http', 'api', 'assets'] satisfies ErrorDependency[];

export const toAppModule = (value: unknown) => (typeof value === 'string' && APP_MODULES.includes(value) ? value as AppModule : null);
export const toErrorOrigin = (value: unknown) => (typeof value === 'string' && ERROR_ORIGINS.includes(value) ? value as ErrorOrigin : null);
export const toErrorDependency = (value: unknown) => (typeof value === 'string' && ERROR_DEPENDENCIES.includes(value) ? value as ErrorDependency : null);
// endregion
