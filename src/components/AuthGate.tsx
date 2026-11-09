import { useEffect, useState, type ReactNode } from 'react';
import { useNavigate, useRouterState } from '@tanstack/react-router';
import { useAccount } from '@/hooks/use-account';
import { getMyBan, type MyBan } from '@/lib/member-ban';
import { supabase } from '@/lib/supabase';

/** Paths reachable without an account. Everything else requires sign-in. */
export const PUBLIC_PATHS = ['/login', '/signup'];

export function isPublicPath(pathname: string) {
  return PUBLIC_PATHS.includes(pathname.replace(/\/+$/, '') || '/');
}

/**
 * Whether the page on screen may be shown. While the router moves to a new
 * address it keeps showing the previous page, so both the address and the page
 * actually on screen must be allowed: signed-out visitors only ever see the
 * sign-in pages, signed-in members never see them.
 */
export function canShowPage(opts: { ready: boolean; signedIn: boolean; path: string; shownPath: string }) {
  if (!opts.ready) return false;
  const pathOpen = isPublicPath(opts.path);
  const shownOpen = isPublicPath(opts.shownPath);
  return opts.signedIn ? !pathOpen && !shownOpen : pathOpen && shownOpen;
}

export function AuthGate({ children }: { children: ReactNode }) {
  return <MemberGate>{children}</MemberGate>;
}

function MemberGate({ children }: { children: ReactNode }) {
  const { session, ready } = useAccount();
  const userId = session?.user.id;
  const [ban, setBan] = useState<MyBan | null>(null);
  useEffect(() => {
    setBan(null);
    if (userId) getMyBan().then(setBan);
  }, [userId]);
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const shownPath = useRouterState({
    select: (s) => s.matches[s.matches.length - 1]?.pathname ?? s.location.pathname,
  });
  const navigate = useNavigate();
  const open = isPublicPath(pathname);

  useEffect(() => {
    if (!ready) return;
    if (!session && !open) navigate({ to: '/login', replace: true });
    if (session && open) navigate({ to: '/', replace: true });
  }, [ready, session, open, navigate]);

  if (!canShowPage({ ready, signedIn: !!session, path: pathname, shownPath })) {
    return <div className="grid h-dvh place-items-center bg-background text-sm text-muted-foreground">…</div>;
  }
  if (session && ban) return <BannedScreen ban={ban} />;
  return <>{children}</>;
}

/** Shown instead of every page while the signed-in member is banned. */
function BannedScreen({ ban }: { ban: MyBan }) {
  return (
    <div className="grid h-dvh place-items-center bg-background px-6 text-center">
      <div className="max-w-sm space-y-3">
        <h1 className="text-xl font-bold">حسابك محظور</h1>
        <p className="text-sm text-muted-foreground">
          {ban.until ? `الحظر لحد ${new Date(ban.until).toLocaleString("ar-EG", { dateStyle: "medium", timeStyle: "short" })}` : "الحظر نهائي"}
        </p>
        {ban.reason && <p className="text-sm">السبب: {ban.reason}</p>}
        <button
          onClick={() => supabase.auth.signOut()}
          className="mt-2 inline-flex items-center justify-center rounded-full bg-secondary px-5 py-2 text-sm font-semibold text-secondary-foreground"
        >
          تسجيل الخروج
        </button>
      </div>
    </div>
  );
}
