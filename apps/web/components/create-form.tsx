"use client";

import { Button, Card } from "@cyberaudit/ui";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api } from "@/lib/api";

export type FieldSpec = {
  name: string;
  label: string;
  type?: "text" | "email" | "password" | "textarea" | "select" | "number" | "date" | "checkbox" | "file" | "datetime";
  required?: boolean;
  placeholder?: string;
  help?: string;
  options?: [string, string][];
  /** Load select options from the API (items[] with id + a label key). */
  optionsFrom?: { path: string; value?: string; label: string };
  defaultValue?: string;
  accept?: string;
  minLength?: number;
  /** Value used when the field is left empty (e.g. a generated external id). */
  generate?: () => string;
};

type Values = Record<string, string | boolean | File | undefined>;

type Props = {
  title: string;
  endpoint: string;
  fields: FieldSpec[];
  submitLabel?: string;
  /** Query keys (endpoint strings) to refresh after success. */
  invalidate?: string[];
  multipart?: boolean;
  /** "PATCH" edits an existing record: only changed fields are sent; cleared optional fields become null. */
  method?: "POST" | "PATCH";
  initialValues?: Record<string, string>;
  onCancel?: () => void;
  onCreated?: (created: unknown) => void;
  className?: string;
};

function SelectOptions({ spec }: { spec: FieldSpec }) {
  const source = spec.optionsFrom;
  const { data } = useQuery({
    queryKey: ["options", source?.path],
    queryFn: () => api<{ items: Record<string, unknown>[] }>(source!.path),
    enabled: Boolean(source),
  });
  const dynamic = (data?.items ?? []).map(
    (item) => [String(item[source?.value ?? "id"]), String(item[source!.label])] as [string, string],
  );
  return (
    <>
      <option value="">Selecionar…</option>
      {[...(spec.options ?? []), ...dynamic].map(([value, label]) => (
        <option key={value} value={value}>
          {label}
        </option>
      ))}
    </>
  );
}

/**
 * Schema-driven create form. It always POSTs to the real API and shows the
 * server's own validation/authorization error -- there is no optimistic or
 * simulated success path.
 */
export function CreateForm({ title, endpoint, fields, submitLabel = "Criar", invalidate = [], multipart, method = "POST", initialValues, onCancel, onCreated, className = "" }: Props) {
  const initial = Object.fromEntries(fields.map((f) => [f.name, f.type === "checkbox" ? false : (initialValues?.[f.name] ?? f.defaultValue ?? "")]));
  const [values, setValues] = useState<Values>(initial);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [done, setDone] = useState<string | null>(null);
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: (body: Values) => {
      if (multipart) {
        const form = new FormData();
        Object.entries(body).forEach(([key, value]) => {
          if (value !== undefined && value !== "") form.append(key, value as string | Blob);
        });
        return api<unknown>(endpoint, { method: "POST", body: form });
      }
      const editing = method === "PATCH";
      const withGenerated = Object.fromEntries(
        Object.entries(body).map(([key, value]) => [key, value === "" ? fields.find((f) => f.name === key)?.generate?.() ?? value : value]),
      );
      const payload = Object.fromEntries(
        Object.entries(withGenerated)
          .filter(([key, value]) => (editing ? value !== initial[key] : value !== ""))
          .map(([key, value]) => [key, editing && value === "" ? null : value])
          .filter(([, value]) => value !== undefined)
          .map(([key, value]) => {
            const spec = fields.find((f) => f.name === key);
            if (spec?.type === "datetime" && typeof value === "string" && value) return [key, new Date(value).toISOString()];
            return [key, spec?.type === "number" && value !== null ? Number(value) : value];
          }),
      );
      return api<unknown>(endpoint, { method, body: JSON.stringify(payload) });
    },
    onSuccess: (created) => {
      setDone(method === "PATCH" ? "Guardado com sucesso." : "Criado com sucesso.");
      if (method === "POST") setValues(initial);
      invalidate.forEach((key) => queryClient.invalidateQueries({ queryKey: [key] }));
      onCreated?.(created);
    },
    onError: () => setDone(null),
  });

  function validate(): boolean {
    const errors: Record<string, string> = {};
    for (const spec of fields) {
      const value = values[spec.name];
      if (spec.required && (value === "" || value === undefined || value === false) && spec.type !== "checkbox") {
        errors[spec.name] = "Campo obrigatório";
      } else if (spec.minLength && typeof value === "string" && value && value.length < spec.minLength) {
        errors[spec.name] = `Mínimo de ${spec.minLength} caracteres`;
      }
    }
    setFieldErrors(errors);
    return Object.keys(errors).length === 0;
  }

  return (
    <Card className={`p-5 ${className}`}>
      <form
        noValidate
        aria-label={title}
        onSubmit={(event) => {
          event.preventDefault();
          setDone(null);
          if (validate()) mutation.mutate(values);
        }}
      >
        <h2 className="mb-4 text-sm font-semibold">{title}</h2>
        <div className="grid gap-4 md:grid-cols-2">
          {fields.map((spec) => {
            const id = `${endpoint}-${spec.name}`.replace(/\W+/g, "-");
            const error = fieldErrors[spec.name];
            const common = {
              id,
              "aria-invalid": Boolean(error),
              "aria-describedby": error ? `${id}-error` : spec.help ? `${id}-help` : undefined,
            };
            const set = (value: string | boolean | File | undefined) => setValues((current) => ({ ...current, [spec.name]: value }));
            return (
              <div key={spec.name} className={spec.type === "textarea" ? "md:col-span-2" : ""}>
                <label htmlFor={id} className="mb-1.5 block text-sm text-muted">
                  {spec.label}
                  {spec.required && <span aria-hidden> *</span>}
                </label>
                {spec.type === "select" ? (
                  <select {...common} className="field" value={String(values[spec.name] ?? "")} onChange={(e) => set(e.target.value)}>
                    <SelectOptions spec={spec} />
                  </select>
                ) : spec.type === "textarea" ? (
                  <textarea {...common} className="field min-h-20" value={String(values[spec.name] ?? "")} onChange={(e) => set(e.target.value)} />
                ) : spec.type === "checkbox" ? (
                  <input {...common} type="checkbox" checked={Boolean(values[spec.name])} onChange={(e) => set(e.target.checked)} />
                ) : spec.type === "file" ? (
                  <input {...common} type="file" accept={spec.accept} className="field" onChange={(e) => set(e.target.files?.[0])} />
                ) : (
                  <input
                    {...common}
                    type={spec.type === "datetime" ? "datetime-local" : (spec.type ?? "text")}
                    className="field"
                    placeholder={spec.placeholder}
                    autoComplete={spec.type === "password" ? "new-password" : undefined}
                    value={String(values[spec.name] ?? "")}
                    onChange={(e) => set(e.target.value)}
                  />
                )}
                {spec.help && !error && (
                  <small id={`${id}-help`} className="text-muted">
                    {spec.help}
                  </small>
                )}
                {error && (
                  <small id={`${id}-error`} className="text-critical">
                    {error}
                  </small>
                )}
              </div>
            );
          })}
        </div>
        <div className="mt-4 flex items-center justify-end gap-3">
          {mutation.error && (
            <p role="alert" className="text-sm text-critical">
              {(mutation.error as Error).message}
            </p>
          )}
          {done && (
            <p role="status" className="text-sm text-green-300">
              {done}
            </p>
          )}
          {onCancel && (
            <button type="button" className="text-sm text-muted hover:underline" onClick={onCancel}>
              Cancelar
            </button>
          )}
          <Button type="submit" disabled={mutation.isPending}>
            {mutation.isPending ? "A guardar…" : submitLabel}
          </Button>
        </div>
      </form>
    </Card>
  );
}
