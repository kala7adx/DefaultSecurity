"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useState, type FormEvent } from "react";

import { Button, ErrorNote } from "@/components/ui";
import { api } from "@/lib/api";
import { safeNext } from "@/lib/safe-next";
import type { Me } from "@/lib/types";

function LoginForm() {
  const router = useRouter();
  const params = useSearchParams();
  const next = safeNext(params.get("next"));
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setBusy(true);
    setError(null);
    try {
      const me = await api<Me>("/auth/login", {
        method: "POST",
        body: { email: String(form.get("email")), password: String(form.get("password")) },
      });
      router.replace(
        me.must_change_password ? `/change-password?next=${encodeURIComponent(next)}` : next,
      );
    } catch (caught) {
      setError(caught);
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="space-y-4">
      <label className="block text-sm">
        Email
        <input
          name="email"
          type="email"
          autoComplete="username"
          required
          className="mt-1 w-full rounded-md border border-slate-300 px-3 py-2"
        />
      </label>
      <label className="block text-sm">
        Password
        <input
          name="password"
          type="password"
          autoComplete="current-password"
          required
          className="mt-1 w-full rounded-md border border-slate-300 px-3 py-2"
        />
      </label>
      <ErrorNote error={error} />
      <Button type="submit" disabled={busy} className="w-full">
        {busy ? "Signing in…" : "Sign in"}
      </Button>
    </form>
  );
}

export default function LoginPage() {
  return (
    <main className="mx-auto mt-24 max-w-sm rounded-lg border border-slate-200 bg-white p-8 shadow-sm">
      <h1 className="mb-6 text-xl font-semibold">Sign in to Skyline</h1>
      <Suspense>
        <LoginForm />
      </Suspense>
    </main>
  );
}
