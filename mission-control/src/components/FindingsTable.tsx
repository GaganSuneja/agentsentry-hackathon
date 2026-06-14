"use client";

import {
  Table,
  TableHeader,
  TableRow,
  TableHeaderCell,
  TableBody,
  TableCell,
  Badge,
  Button,
  makeStyles,
  tokens,
} from "@fluentui/react-components";
import { Eye20Regular } from "@fluentui/react-icons";
import Link from "next/link";
import { formatCategory, sortFindingsBySeverity } from "@/lib/attacks";
import type { Finding } from "@/types/api";

const useStyles = makeStyles({
  table: {
    width: "100%",
    border: `1px solid ${tokens.colorNeutralStroke2}`,
    borderRadius: tokens.borderRadiusMedium,
  },
  meta: {
    fontSize: tokens.fontSizeBase200,
    color: tokens.colorNeutralForeground3,
  },
  judgment: {
    fontSize: tokens.fontSizeBase300,
    maxWidth: "280px",
    display: "inline-block",
    color: tokens.colorNeutralForeground2,
  },
});

function severityColor(severity: string): "danger" | "warning" | "informative" | "subtle" {
  switch (severity.toLowerCase()) {
    case "critical":
    case "high":
      return "danger";
    case "medium":
      return "warning";
    default:
      return "informative";
  }
}

function statusColor(status: string): "danger" | "success" | "warning" {
  switch (status) {
    case "vulnerable":
      return "danger";
    case "defended":
      return "success";
    default:
      return "warning";
  }
}

function extractJudgeRationale(evidence: Record<string, unknown>): string | null {
  if (typeof evidence.judgment === "string") {
    return evidence.judgment;
  }

  const llmJudge = evidence.llm_judge;
  if (typeof llmJudge !== "object" || llmJudge === null) {
    return null;
  }

  const rationale = (llmJudge as { rationale?: unknown }).rationale;
  return typeof rationale === "string" ? rationale : null;
}

export function FindingsTable({
  findings,
  scanId,
}: {
  findings: Finding[];
  scanId: string;
}) {
  const styles = useStyles();
  const sorted = sortFindingsBySeverity(findings);

  if (sorted.length === 0) {
    return null;
  }

  return (
    <Table className={styles.table} aria-label="Scan findings">
      <TableHeader>
        <TableRow>
          <TableHeaderCell>Attack</TableHeaderCell>
          <TableHeaderCell>Severity</TableHeaderCell>
          <TableHeaderCell>Status</TableHeaderCell>
          <TableHeaderCell>Category</TableHeaderCell>
          <TableHeaderCell>Judgment</TableHeaderCell>
          <TableHeaderCell>Trace</TableHeaderCell>
        </TableRow>
      </TableHeader>
      <TableBody>
        {sorted.map((finding) => {
          const judgment = extractJudgeRationale(finding.evidence);

          return (
            <TableRow key={finding.id}>
              <TableCell>
                <div>
                  <strong>{finding.attack_name}</strong>
                  <div className={styles.meta}>{finding.attack_id}</div>
                </div>
              </TableCell>
              <TableCell>
                <Badge color={severityColor(finding.severity)} appearance="outline">
                  {finding.severity}
                </Badge>
              </TableCell>
              <TableCell>
                <Badge color={statusColor(finding.status)} appearance="filled">
                  {finding.status.toUpperCase()}
                </Badge>
              </TableCell>
              <TableCell>{formatCategory(finding.category)}</TableCell>
              <TableCell>
                <span className={styles.judgment}>{judgment ?? "—"}</span>
              </TableCell>
              <TableCell>
                <Link
                  href={`/findings/detail/?scanId=${encodeURIComponent(scanId)}&findingId=${encodeURIComponent(finding.id)}`}
                >
                  <Button appearance="subtle" icon={<Eye20Regular />}>
                    View trace
                  </Button>
                </Link>
              </TableCell>
            </TableRow>
          );
        })}
      </TableBody>
    </Table>
  );
}
