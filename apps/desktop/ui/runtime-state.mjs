const RESOURCE_LABELS = Object.freeze({
  "cyberaudit-postgres": "PostgreSQL local",
  "cyberaudit-valkey": "Broker local",
  "cyberaudit-api": "API CyberAudit",
  "cyberaudit-worker": "Worker CyberAudit",
  "cyberaudit-web": "Interface CyberAudit",
  "manifest.json": "Manifesto do runtime",
});

export function runtimePresentation(status) {
  if (status?.ready && status?.state === "resources_verified") {
    return {
      kind: "progress",
      title: "Componentes locais verificados",
      message:
        "A integridade do runtime foi confirmada. O supervisor pode iniciar os serviços locais.",
      statusText: "Integridade confirmada",
      resources: [],
      retry: false,
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
  };
}
