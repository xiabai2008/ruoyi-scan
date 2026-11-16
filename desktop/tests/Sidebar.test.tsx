import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  app: { current: {} as Record<string, unknown> },
  persona: { current: {} as Record<string, unknown> },
}));

vi.mock("../src/state/AppCtx", () => ({ useApp: () => mocks.app.current }));
vi.mock("../src/state/PersonaCtx", () => ({
  usePersona: () => mocks.persona.current,
  operatorAvatarSrc: () => "avatar.png",
}));

import { Sidebar } from "../src/components/Sidebar";
import { NAV } from "../src/data/mock";

describe("Sidebar", () => {
  beforeEach(() => {
    mocks.app.current = {
      view: "overview",
      setView: vi.fn(),
      online: true,
      engine: { version: "1.7.0" },
      tasks: [],
    };
    mocks.persona.current = {
      operator: { callsign: "TEST", greet: "开工", avatar: "" },
    };
  });

  it("渲染全部 7 个导航项", () => {
    render(<Sidebar />);
    for (const item of NAV) {
      expect(screen.getByText(item.label)).toBeInTheDocument();
    }
    expect(screen.getByText("v1.7.0")).toBeInTheDocument();
  });

  it("点击导航调用 setView(id)", () => {
    const setView = vi.fn();
    mocks.app.current = { ...mocks.app.current, setView };
    render(<Sidebar />);
    fireEvent.click(screen.getByText("漏洞库"));
    expect(setView).toHaveBeenCalledWith("vulndb");
  });
});
