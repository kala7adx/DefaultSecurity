import { Suspense } from "react";

import { FindingsView } from "@/components/findings-view";

export default function FindingsPage() {
  return (
    <Suspense>
      <FindingsView openId={null} />
    </Suspense>
  );
}
