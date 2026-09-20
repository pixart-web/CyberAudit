import { cleanup, render, screen, fireEvent } from "@testing-library/react";
import { useState } from "react";
import { afterEach, expect, test } from "vitest";
import { EmptyState, ErrorState, SeverityBadge, Tabs, TabPanel, toSecurityState } from "@cyberaudit/ui";

afterEach(cleanup);

test("toSecurityState maps common backend strings onto the semantic scale", () => {
  expect(toSecurityState("critical")).toBe("critical");
  expect(toSecurityState("active")).toBe("healthy");
  expect(toSecurityState("pending_authorization")).toBe("warning");
  expect(toSecurityState("blocked")).toBe("failed");
  expect(toSecurityState("something-never-seen")).toBe("unknown");
});

test("SeverityBadge never relies on color alone: every state has a text label", () => {
  render(<SeverityBadge state="critical" />);
  expect(screen.getByText("Crítico")).toBeInTheDocument();
  render(<SeverityBadge state="not-a-real-status" />);
  expect(screen.getByText("Desconhecido")).toBeInTheDocument();
});

test("EmptyState and ErrorState expose their status to assistive technology", () => {
  render(<EmptyState title="Ainda não existem registos." />);
  expect(screen.getByRole("status")).toHaveTextContent("Ainda não existem registos.");
  render(<ErrorState />);
  expect(screen.getByRole("alert")).toHaveTextContent("Não foi possível carregar os dados.");
});

function TabsHarness() {
  const [active, setActive] = useState("overview");
  return (
    <div>
      <Tabs
        items={[
          { id: "overview", label: "Visão Geral" },
          { id: "scope", label: "Âmbito" },
        ]}
        active={active}
        onChange={setActive}
      />
      <TabPanel id="overview" active={active}>
        Overview content
      </TabPanel>
      <TabPanel id="scope" active={active}>
        Scope content
      </TabPanel>
    </div>
  );
}

test("Tabs switches panels and exposes correct aria-selected state", () => {
  render(<TabsHarness />);
  expect(screen.getByText("Overview content")).toBeInTheDocument();
  expect(screen.queryByText("Scope content")).not.toBeInTheDocument();
  expect(screen.getByRole("tab", { name: "Visão Geral" })).toHaveAttribute("aria-selected", "true");

  fireEvent.click(screen.getByRole("tab", { name: "Âmbito" }));

  expect(screen.getByText("Scope content")).toBeInTheDocument();
  expect(screen.queryByText("Overview content")).not.toBeInTheDocument();
  expect(screen.getByRole("tab", { name: "Âmbito" })).toHaveAttribute("aria-selected", "true");
});

test("Tabs supports arrow-key navigation between tabs", () => {
  render(<TabsHarness />);
  const first = screen.getByRole("tab", { name: "Visão Geral" });
  first.focus();
  fireEvent.keyDown(first, { key: "ArrowRight" });
  expect(screen.getByText("Scope content")).toBeInTheDocument();
});
