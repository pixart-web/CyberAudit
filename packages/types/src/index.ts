export type Severity = "critical" | "high" | "medium" | "low";
export type EngagementStatus =
  | "draft"
  | "pending_authorization"
  | "authorized"
  | "active"
  | "paused"
  | "completed"
  | "cancelled";
export interface Page<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}
