"use client";

import {
  Text,
  makeStyles,
  tokens,
  Card,
  Badge,
} from "@fluentui/react-components";
import type { Finding } from "@/types/api";

const useStyles = makeStyles({
  timeline: {
    display: "flex",
    flexDirection: "column",
    gap: tokens.spacingVerticalM,
  },
  step: {
    borderLeft: `3px solid ${tokens.colorBrandStroke1}`,
    paddingLeft: tokens.spacingHorizontalL,
    paddingBottom: tokens.spacingVerticalM,
  },
  stepTitle: {
    fontWeight: tokens.fontWeightSemibold,
    marginBottom: tokens.spacingVerticalXS,
  },
  codeBlock: {
    fontFamily: tokens.fontFamilyMonospace,
    fontSize: tokens.fontSizeBase200,
    backgroundColor: tokens.colorNeutralBackground3,
    padding: tokens.spacingHorizontalM,
    borderRadius: tokens.borderRadiusSmall,
    whiteSpace: "pre-wrap",
    wordBreak: "break-word",
    marginTop: tokens.spacingVerticalXS,
  },
  toolCall: {
    border: `1px solid ${tokens.colorNeutralStroke2}`,
    borderRadius: tokens.borderRadiusSmall,
    padding: tokens.spacingHorizontalS,
    marginTop: tokens.spacingVerticalXS,
    backgroundColor: tokens.colorNeutralBackground2,
  },
  compromised: {
    border: `1px solid ${tokens.colorPaletteRedBorder2}`,
    backgroundColor: tokens.colorPaletteRedBackground1,
  },
});

interface TraceStep {
  title: string;
  content: React.ReactNode;
}

function formatJudgeBackend(backend: string): string {
  switch (backend) {
    case "azure_openai":
      return "Azure OpenAI Judge";
    case "heuristic_demo":
      return "Demo Mode Heuristic";
    default:
      return backend;
  }
}

function renderJson(value: unknown): string {
  if (typeof value === "string") return value;
  return JSON.stringify(value, null, 2);
}

function buildTraceSteps(
  finding: Finding,
  styles: ReturnType<typeof useStyles>,
): TraceStep[] {
  const { evidence } = finding;
  const steps: TraceStep[] = [];

  if (evidence.attack_setup) {
    steps.push({
      title: "1. Attack setup",
      content: (
        <pre className={styles.codeBlock}>
          {renderJson(evidence.attack_setup)}
        </pre>
      ),
    });
  }

  const promptFields: Array<[string, string]> = [
    ["user_prompt", "2. User prompt sent"],
    ["spoofed_message", "2. Spoofed inter-agent message"],
    ["benign_trigger", "2. Benign trigger prompt"],
  ];

  for (const [key, title] of promptFields) {
    if (evidence[key]) {
      steps.push({
        title,
        content: (
          <pre className={styles.codeBlock}>{renderJson(evidence[key])}</pre>
        ),
      });
    }
  }

  if (evidence.agent_response_text) {
    steps.push({
      title: "3. Agent response",
      content: (
        <pre className={styles.codeBlock}>
          {renderJson(evidence.agent_response_text)}
        </pre>
      ),
    });
  }

  const toolCalls = evidence.agent_tool_calls as
    | Array<{ name: string; arguments?: Record<string, unknown> }>
    | undefined;
  const compromised = new Set(
    ((evidence.compromised_tool_calls as Array<{ name: string }>) ?? []).map(
      (t) => t.name,
    ),
  );

  if (toolCalls?.length) {
    steps.push({
      title: "4. Tool calls",
      content: (
        <>
          {toolCalls.map((call, i) => (
            <div
              key={`${call.name}-${i}`}
              className={`${styles.toolCall} ${compromised.has(call.name) ? styles.compromised : ""}`}
            >
              <strong>{call.name}</strong>
              {compromised.has(call.name) && (
                <Badge color="danger" appearance="filled" style={{ marginLeft: 8 }}>
                  COMPROMISED
                </Badge>
              )}
              {call.arguments && (
                <pre className={styles.codeBlock}>
                  {renderJson(call.arguments)}
                </pre>
              )}
            </div>
          ))}
        </>
      ),
    });
  }

  if (evidence.judgment) {
    steps.push({
      title: "5. Judgment",
      content: (
        <pre className={styles.codeBlock}>
          {renderJson(evidence.judgment)}
        </pre>
      ),
    });
  }

  const llmJudge = evidence.llm_judge as
    | {
        succeeded?: boolean;
        rationale?: string;
        backend?: string;
      }
    | undefined;

  if (llmJudge) {
    steps.push({
      title: "5. Judge verdict",
      content: (
        <>
          <div style={{ display: "flex", gap: 8, marginBottom: 8 }}>
            {llmJudge.backend && (
              <Badge appearance="outline">
                {formatJudgeBackend(llmJudge.backend)}
              </Badge>
            )}
            {typeof llmJudge.succeeded === "boolean" && (
              <Badge
                color={llmJudge.succeeded ? "danger" : "success"}
                appearance="filled"
              >
                {llmJudge.succeeded ? "ATTACK SUCCEEDED" : "ATTACK BLOCKED"}
              </Badge>
            )}
          </div>
          <pre className={styles.codeBlock}>{renderJson(llmJudge)}</pre>
        </>
      ),
    });
  }

  if (steps.length === 0) {
    steps.push({
      title: "Raw evidence",
      content: (
        <pre className={styles.codeBlock}>
          {renderJson(evidence)}
        </pre>
      ),
    });
  }

  if (finding.remediation) {
    steps.push({
      title: "6. Remediation",
      content: <Text>{finding.remediation}</Text>,
    });
  }

  return steps;
}

export function EvidenceTrace({ finding }: { finding: Finding }) {
  const styles = useStyles();
  const steps = buildTraceSteps(finding, styles);

  return (
    <Card>
      <div style={{ marginBottom: 16 }}>
        <Text weight="semibold" size={500}>
          {finding.attack_name}
        </Text>
        <div style={{ marginTop: 8, display: "flex", gap: 8 }}>
          <Badge color="danger" appearance="outline">
            {finding.severity}
          </Badge>
          <Badge
            color={finding.status === "vulnerable" ? "danger" : "success"}
            appearance="filled"
          >
            {finding.status.toUpperCase()}
          </Badge>
        </div>
      </div>
      <div className={styles.timeline}>
        {steps.map((step) => (
          <div key={step.title} className={styles.step}>
            <Text className={styles.stepTitle}>{step.title}</Text>
            {step.content}
          </div>
        ))}
      </div>
    </Card>
  );
}
