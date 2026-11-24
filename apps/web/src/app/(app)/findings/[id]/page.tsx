import { Suspense } from "react";

import { FindingsView } from "@/components/findings-view";

/** Deep link target (/findings/<id>): the list with that finding's drawer open. */
export default async function FindingPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return (
    <Suspense>
      <FindingsView openId={id} />
    </Suspense>
  );
}
