import { supabase } from '@/lib/supabase';
import rose from '@/assets/gifts/rose.webp';
import star from '@/assets/gifts/star.webp';
import bouquet from '@/assets/gifts/bouquet.webp';
import ring from '@/assets/gifts/ring.webp';
import wolf from '@/assets/gifts/wolf.webp';
import diamond from '@/assets/gifts/diamond.webp';
import lion from '@/assets/gifts/lion.webp';
import dragon from '@/assets/gifts/dragon.webp';

/** Built-in gift pictures by catalog key (supabase/006_room_gifts.sql); a catalog art_url overrides them. A gift with neither is not shown. */
export const GIFT_ART: Record<string, string> = { rose, star, bouquet, ring, wolf, diamond, lion, dragon };

export type Gift = { key: string; name: string; price: number; art: string };

/** Counts offered in the picker; the database accepts 1–9999. */
export const GIFT_QUANTITIES = [1, 10, 66, 99, 188, 520] as const;

/** Whole cost of one send: price x count x number of people. */
export const giftCost = (price: number, quantity: number, people: number) => price * quantity * people;

type CatalogRow = { key: string; name: string; price: number; art_url?: string | null };

/** Picture for a gift: the catalog's art_url when set, otherwise the built-in picture. */
export const giftArt = (row: Pick<CatalogRow, 'key' | 'art_url'>): string | undefined =>
  row.art_url?.trim() || GIFT_ART[row.key];

/** Rows to gifts: keeps every row that has a picture (art_url or built-in), drops the rest. */
export const toGifts = (rows: CatalogRow[]): Gift[] =>
  rows.flatMap((g) => {
    const art = giftArt(g);
    return art ? [{ key: g.key, name: g.name, price: Number(g.price), art }] : [];
  });

/** True when the database has no art_url column yet (update 013 not run). */
const missingArtUrl = (error: { code?: string; message?: string }) =>
  error.code === '42703' || error.code === 'PGRST204' || /art_url/.test(error.message ?? '');

/** Active gifts with a picture, cheapest first. Prices come from the database. */
export async function getGiftCatalog(): Promise<Gift[]> {
  const catalog = (columns: string) => supabase.from('room_gift_catalog').select(columns).eq('active', true).order('sort');
  let { data, error } = await catalog('key, name, price, sort, art_url');
  if (error && missingArtUrl(error)) ({ data, error } = await catalog('key, name, price, sort'));
  if (error) throw error;
  return toGifts((data ?? []) as unknown as CatalogRow[]);
}

/** Sends one gift x count to every picked person. Returns the room's new total. */
export async function sendRoomGift(roomId: string, gift: string, quantity: number, to: string[]): Promise<number> {
  const { data, error } = await supabase.rpc('send_room_gift', { p_room: roomId, p_gift: gift, p_quantity: quantity, p_to: to });
  if (error) throw error;
  return Number(data ?? 0) || 0;
}

/** What each person received in this room, by auth ID. Missing update = nothing yet. */
export async function getGiftsReceived(roomId: string): Promise<Record<string, number>> {
  const { data, error } = await supabase.rpc('room_gifts_received', { p_room: roomId });
  if (error) return {};
  return Object.fromEntries(((data ?? []) as { auth_id: string; total: number }[]).map((r) => [r.auth_id, Number(r.total) || 0]));
}

export const giftErrorMessage = (hint: string | undefined) =>
  ({
    not_enough_coins: 'رصيدك من الكوينز مش كفاية',
    not_in_room: 'لازم تكون جوه الروم',
    recipient_left: 'في حد من اللي اخترتهم خرج من الروم',
    no_recipient: 'اختار مين هياخد الهدية',
    bad_gift: 'الهدية دي مش متاحة',
    bad_amount: 'العدد ده مش مسموح',
  })[hint ?? ''] ?? 'الهدية ماتبعتتش';
