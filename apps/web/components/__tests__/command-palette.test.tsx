import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, test } from "vitest";
import { CommandPalette } from "../command-palette";

afterEach(cleanup);

const items = [
  { label: "Command Center", href: "/command-center", group: "Operações" },
  { label: "Findings", href: "/findings", group: "Resultados" },
  { label: "Cyber AI Workspace", href: "/cyber-agents", group: "Intelligence" },
];

test("opens with Cmd/Ctrl+K and filters by label", () => {
  render(<CommandPalette items={items} />);
  expect(screen.queryByRole("dialog")).not.toBeInTheDocument();

  fireEvent.keyDown(document, { key: "k", metaKey: true });
  expect(screen.getByRole("dialog", { name: "Paleta de comandos" })).toBeInTheDocument();

  const input = screen.getByRole("combobox");
  fireEvent.change(input, { target: { value: "finding" } });
  expect(screen.getByText("Findings")).toBeInTheDocument();
  expect(screen.queryByText("Command Center")).not.toBeInTheDocument();
});

test("closes on Escape", () => {
  render(<CommandPalette items={items} />);
  fireEvent.keyDown(document, { key: "k", ctrlKey: true });
  expect(screen.getByRole("dialog")).toBeInTheDocument();
  fireEvent.keyDown(document, { key: "Escape" });
  expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
});

test("never exposes an arbitrary command input -- only fixed, known routes are listed", () => {
  render(<CommandPalette items={items} />);
  fireEvent.keyDown(document, { key: "k", metaKey: true });
  fireEvent.change(screen.getByRole("combobox"), { target: { value: "rm -rf" } });
  expect(screen.getByText("Sem correspondências.")).toBeInTheDocument();
});
