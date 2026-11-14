const RESOURCE_LABELS = Object.freeze({
  "cyberaudit-postgres": "PostgreSQL local",
  "cyberaudit-valkey": "Broker local",
  "cyberaudit-api": "API CyberAudit",
  "cyberaudit-worker": "Worker CyberAudit",
  "cyberaudit-web": "Interface CyberAudit",
  "manifest.json": "Manifesto do runtime",
});

export function runtimePresentation(status) {
  if (status?.state === "verifying_resources") {
    return {
      kind: "progress",
      title: "A verificar o CyberAudit OS",
      message:
        "A validar a integridade dos componentes locais antes do arranque.",
      statusText: "Verificação em curso",
      resources: [],
      retry: false,
      action: null,
    };
  }

  if (status?.state === "resources_verified") {
    return {
      kind: "progress",
      title: "Componentes locais verificados",
      message:
        "A integridade do runtime foi confirmada. O supervisor pode iniciar os serviços locais.",
      statusText: "Integridade confirmada",
      resources: [],
      retry: false,
      action: null,
    };
  }

  if (status?.ready && status?.state === "ready") {
    return {
      kind: "progress",
      title: "Runtime local pronto",
      message: "A interface segura do CyberAudit está a ser aberta.",
      statusText: "Serviços locais disponíveis",
      resources: [],
      retry: false,
      action: null,
    };
  }

  if (status?.state === "credential_migration_required") {
    return {
      kind: "error",
      title: "Migração segura necessária",
      message:
        "Foram encontrados dados de uma instalação anterior. Migre explicitamente as credenciais do Keychain; os valores existentes não serão eliminados nem substituídos.",
      statusText: "A aguardar autorização do Keychain",
      resources: [],
      retry: false,
      action: "migrate_credentials",
    };
  }

  if (status?.state === "credentials_migrated_restart_required") {
    return {
      kind: "progress",
      title: "Credenciais migradas",
      message:
        "A cópia segura foi concluída e o conjunto legado foi preservado. Reinicie o CyberAudit OS para validar e iniciar os serviços.",
      statusText: "Reinício necessário",
      resources: [],
      retry: false,
      action: null,
    };
  }

  const affected = [
    ...(Array.isArray(status?.missing_resources)
      ? status.missing_resources
      : []),
    ...(Array.isArray(status?.invalid_resources)
      ? status.invalid_resources
      : []),
  ];
  const resources = [...new Set(affected)]
    .filter((name) => typeof name === "string" && name in RESOURCE_LABELS)
    .map((name) => RESOURCE_LABELS[name]);

  return {
    kind: "error",
    title: "Runtime local indisponível",
    message:
      "O CyberAudit bloqueou o arranque porque faltam componentes ou a sua integridade não pôde ser confirmada.",
    statusText: "Arranque bloqueado de forma segura",
    resources,
    retry: true,
    action: "retry",
  };
}

export function runtimeFailurePresentation() {
  return {
    kind: "error",
    title: "Não foi possível verificar o runtime",
    message:
      "A fronteira nativa não respondeu. Reinicie a aplicação ou consulte os logs sanitizados de diagnóstico.",
    statusText: "Falha de verificação",
    resources: [],
    retry: true,
    action: "retry",
  };
}
