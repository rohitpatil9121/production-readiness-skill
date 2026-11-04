#!/usr/bin/env bash
set -e
mkdir -p src supabase/migrations
cat > package.json <<'J'
{ "name": "journal", "dependencies": { "react": "^18.3.1", "@supabase/supabase-js": "^2.45.0", "vite": "^5.4.0" } }
J
cat > supabase/migrations/0001_init.sql <<'S'
create table public.entries (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users not null,
  body text not null,
  created_at timestamptz default now()
);
S
cat > src/supabase.js <<'J'
import { createClient } from "@supabase/supabase-js";
export const supabase = createClient(import.meta.env.VITE_SUPABASE_URL, import.meta.env.VITE_SUPABASE_ANON_KEY);
J
cat > src/Entries.jsx <<'J'
import { supabase } from "./supabase";
export async function loadEntries(userId) {
  const { data } = await supabase.from("entries").select("*").eq("user_id", userId);
  return data;
}
J
