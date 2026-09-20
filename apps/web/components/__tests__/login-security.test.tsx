import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { expect, test, vi } from "vitest";
import LoginPage from "@/app/login/page";

vi.mock("next/navigation",()=>({useRouter:()=>({push:vi.fn()})}));

test("native login fallback never serializes credentials into a GET URL",()=>{
  const {container}=render(<QueryClientProvider client={new QueryClient()}><LoginPage/></QueryClientProvider>);
  expect(container.querySelector("form")).toHaveAttribute("method","post");
  expect(screen.getByRole("button",{name:"Entrar na plataforma"})).toHaveAttribute("type","submit");
  expect(screen.getByLabelText("Password")).toHaveAttribute("type","password");
});
