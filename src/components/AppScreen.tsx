import type { ReactNode } from "react";
import { BottomNav } from "@/components/BottomNav";

export function AppScreen({ children, navigation = true }: { children: ReactNode; navigation?: boolean }) {
  return (
    <div className="h-dvh overflow-hidden bg-muted md:p-8">
      <div className="relative mx-auto flex h-full w-full max-w-md flex-col overflow-hidden bg-background md:rounded-[2.5rem] md:border md:shadow-soft">
        <main className="min-h-0 flex-1 overflow-y-auto overscroll-contain pb-6 [scrollbar-width:thin]">
          {children}
        </main>
        {navigation && <BottomNav />}
      </div>
    </div>
  );
}