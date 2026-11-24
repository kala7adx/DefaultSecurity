"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useState, type FormEvent } from "react";

import { Button, ErrorNote } from "@/components/ui";
import { api } from "@/lib/api";
import { safeNext } from "@/lib/safe-next";

function ChangePasswordForm() {
  const router = useRouter();
  const next = safeNext(useSearchParams().get("next"));
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    if (form.get("new_password") !== form.get("confirm")) {
      setError(new Error("The new passwords don't match"));
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await api("/auth/change-password", {
        method: "POST",
        body: {
          current_password: String(form.get("current_password")),
          new_password: String(form.get("new_password")),
        },
      });
      router.replace(next);
    } catch (caught) {
      setError(caught);
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="space-y-4">
      {(
        [
          ["current_password", "Current password", "current-password"],
          ["new_password", "New password (12+ characters)", "new-password"],
          ["confirm", "Confirm new password", "new-password"],
        ] as const
      ).map(([name, label, autoComplete]) => (
        <label key={name} className="block text-sm">
          {label}
          <input
            name={name}
            type="password"
            autoComplete={autoComplete}
            required
            minLength={name === "current_password" ? 1 : 12}
            className="mt-1 w-full rounded-md border border-slate-300 px-3 py-2"
          />
        </label>
      ))}
      <ErrorNote error={error} />
      <Button type="submit" disabled={busy} className="w-full">
        {busy ? "Saving…" : "Change password"}
      </Button>
    </form>
  );
}

export default function ChangePasswordPage() {
  return (
    <main className="mx-auto mt-24 max-w-sm rounded-lg border border-slate-200 bg-white p-8 shadow-sm">
      <h1 className="mb-2 text-xl font-semibold">Choose a new password</h1>
      <p className="mb-6 text-sm text-slate-600">You need a new password before you continue.</p>
      <Suspense>
        <ChangePasswordForm />
      </Suspense>
    </main>
  );
}
