export interface CoverageInformationForm {
  readonly coverage_name: string | null;
  readonly coverage_score: number | null;
}

export interface CoverageInformation {
  readonly coverage_name: string;
  readonly coverage_score: number;
}
