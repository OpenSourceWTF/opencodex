import { afterEach, beforeEach, expect, test } from "bun:test";
import { Window } from "happy-dom";
import { act } from "react";
import type { Root } from "react-dom/client";
import ProviderSettings from "../src/components/provider-workspace/ProviderSettings";
import type { ProviderUpdatePatch } from "../src/components/provider-workspace/types";
import { AddProviderFormPane } from "../src/components/add-provider-form-pane";
import { LanguageProvider } from "../src/i18n/provider";
import type { WorkspaceItem } from "../src/provider-workspace/catalog";
import { buildProviderPayload, type ProviderPayloadForm } from "../src/provider-payload";

// The Bedrock browser SSO login is a user-consent action: it must stay off unless the user ticks it.

const globals = ["document", "window", "navigator", "localStorage", "IS_REACT_ACT_ENVIRONMENT"] as const;
let previous: Record<string, unknown>;
let win: Window;
let root: Root | undefined;
beforeEach(() => {
  previous = Object.fromEntries(globals.map(key => [key, Reflect.get(globalThis, key)]));
  win = new Window({ url: "http://localhost/#providers" });
  Object.defineProperty(win.navigator, "language", { configurable: true, value: "en-US" });
  for (const [key, value] of Object.entries({ document: win.document, window: win, navigator: win.navigator, localStorage: win.localStorage, IS_REACT_ACT_ENVIRONMENT: true })) {
    Object.defineProperty(globalThis, key, { configurable: true, writable: true, value });
  }
});
afterEach(async () => {
  await act(async () => { root?.unmount(); });
  root = undefined;
  win.close();
  for (const key of globals) Object.defineProperty(globalThis, key, { configurable: true, writable: true, value: previous[key] });
});

const ssoBox = (container: HTMLElement) => container.querySelector<HTMLInputElement>("input[data-bedrock-sso-login]");
const bedrock = (overrides: Partial<WorkspaceItem> = {}): WorkspaceItem => ({
  name: "amazon-bedrock", adapter: "bedrock", baseUrl: "https://bedrock-runtime.us-east-1.amazonaws.com", authMode: "key",
  keyOptional: true, region: "us-east-1", awsProfile: "personal", ...overrides,
});

test("the add payload writes awsSsoAutoLogin only for an explicit tick", () => {
  const form: ProviderPayloadForm = {
    name: "amazon-bedrock", adapter: "bedrock", baseUrl: "https://bedrock-runtime.us-east-1.amazonaws.com", authMode: "key",
    apiKey: "", defaultModel: "", region: "us-east-1", awsProfile: "personal", awsSsoAutoLogin: false,
  };
  expect(buildProviderPayload(form)).not.toHaveProperty("awsSsoAutoLogin");
  expect(buildProviderPayload({ ...form, awsSsoAutoLogin: undefined })).not.toHaveProperty("awsSsoAutoLogin");
  expect(buildProviderPayload({ ...form, awsSsoAutoLogin: true }).awsSsoAutoLogin).toBe(true);
  expect(buildProviderPayload({ ...form, adapter: "anthropic", awsSsoAutoLogin: true })).not.toHaveProperty("awsSsoAutoLogin");
});

test("the add form shows the SSO login box unticked by default", async () => {
  let form: ProviderPayloadForm = {
    name: "amazon-bedrock", adapter: "bedrock", baseUrl: "https://bedrock-runtime.us-east-1.amazonaws.com", authMode: "key",
    apiKey: "", defaultModel: "", region: "us-east-1", awsProfile: "", awsSsoAutoLogin: false,
  };
  const container = document.createElement("div");
  document.body.append(container);
  const { createRoot } = await import("react-dom/client");
  root = createRoot(container);
  const render = () => root!.render(<LanguageProvider><AddProviderFormPane
    preset={{ id: "amazon-bedrock", label: "Amazon Bedrock (Claude)", adapter: "bedrock", baseUrl: form.baseUrl, auth: "key", keyOptional: true, region: "us-east-1" }}
    form={form} endpointChoice="custom" error="" saving={false} dup={false} isCustom={false} isLocal={false} isReservedForward={false}
    presetDescription={() => undefined} onFormChange={next => { form = next; render(); }}
    onEndpointChoiceChange={() => undefined} onSubmit={() => undefined} onUseOauthLogin={() => undefined} onBack={() => undefined}
  /></LanguageProvider>);
  await act(async () => { render(); });
  expect(ssoBox(container)?.checked).toBe(false);
  await act(async () => { ssoBox(container)!.click(); });
  expect(form.awsSsoAutoLogin).toBe(true);
  expect(buildProviderPayload(form).awsSsoAutoLogin).toBe(true);
});

test("settings: an unset value shows unticked, ticking saves true, unticking clears it", async () => {
  const patches: ProviderUpdatePatch[] = [];
  const container = document.createElement("div");
  document.body.append(container);
  const { createRoot } = await import("react-dom/client");
  const render = async (item: WorkspaceItem) => act(async () => {
    root ??= createRoot(container);
    root.render(<LanguageProvider><ProviderSettings item={item} onUpdateProvider={async (_name, patch) => { patches.push(patch); return { ok: true }; }} /></LanguageProvider>);
  });
  const save = async () => {
    const button = container.querySelector<HTMLButtonElement>(".pwi-settings-sticky-bar .btn-primary");
    expect(button).toBeTruthy();
    await act(async () => { button!.click(); });
  };
  await render(bedrock());
  expect(ssoBox(container)?.checked).toBe(false);
  await act(async () => { ssoBox(container)!.click(); });
  await save();
  expect(patches[0]?.awsSsoAutoLogin).toBe(true);
  await render(bedrock({ awsSsoAutoLogin: true }));
  expect(ssoBox(container)?.checked).toBe(true);
  await act(async () => { ssoBox(container)!.click(); });
  await save();
  expect(patches[1]?.awsSsoAutoLogin).toBeNull();
});
