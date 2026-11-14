import {
  runtimeFailurePresentation,
  runtimePresentation,
} from "./runtime-state.mjs";

const elements = {
  title: document.querySelector("#title"),
  message: document.querySelector("#message"),
  status: document.querySelector(".status"),
  statusText: document.querySelector("#status-text"),
  resources: document.querySelector("#resources"),
  retry: document.querySelector("#retry"),
};

function render(presentation) {
  elements.title.textContent = presentation.title;
  elements.message.textContent = presentation.message;
  elements.status.dataset.kind = presentation.kind;
  elements.statusText.textContent = presentation.statusText;
  elements.retry.hidden = presentation.action === null;
  elements.retry.dataset.action = presentation.action ?? "";
  elements.retry.textContent =
    presentation.action === "migrate_credentials"
      ? "Migrar credenciais do Keychain"
      : "Verificar novamente";
  elements.resources.replaceChildren(
    ...presentation.resources.map((resource) => {
      const item = document.createElement("li");
      item.textContent = `— ${resource}`;
      return item;
    }),
  );
}

async function verifyRuntime() {
  elements.retry.disabled = true;
  try {
    const status = await window.__TAURI__.core.invoke("desktop_runtime_status");
    render(runtimePresentation(status));
  } catch {
    render(runtimeFailurePresentation());
  } finally {
    elements.retry.disabled = false;
  }
}

async function migrateCredentials() {
  elements.retry.disabled = true;
  try {
    const status = await window.__TAURI__.core.invoke(
      "desktop_migrate_legacy_credentials",
    );
    render(runtimePresentation(status));
  } catch {
    render(runtimeFailurePresentation());
  } finally {
    elements.retry.disabled = false;
  }
}

elements.retry.addEventListener("click", () => {
  if (elements.retry.dataset.action === "migrate_credentials") {
    void migrateCredentials();
    return;
  }
  void verifyRuntime();
});
void verifyRuntime();
