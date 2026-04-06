export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    const corsHeaders = {
      "Access-Control-Allow-Origin": "https://sikkmixx.com",
      "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Access-Control-Max-Age": "86400",
    };

    const json = (obj, status = 200, extraHeaders = {}) =>
      new Response(JSON.stringify(obj), {
        status,
        headers: {
          ...corsHeaders,
          "Content-Type": "application/json",
          ...extraHeaders,
        },
      });

    const text = (msg, status = 200, extraHeaders = {}) =>
      new Response(msg, {
        status,
        headers: { ...corsHeaders, ...extraHeaders },
      });

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    // ---------------- AUTH HELPERS ----------------

    function parseTokenFromRequest(req) {
      const auth = req.headers.get("Authorization") || "";
      if (!auth.startsWith("Bearer ")) return null;

      const raw = auth.slice("Bearer ".length).trim();
      if (!raw) return null;

      try {
        const payload = JSON.parse(atob(raw));
        if (!payload || typeof payload !== "object") return null;

        // exp is ms timestamp
        if (!payload.exp || typeof payload.exp !== "number") return null;
        if (payload.exp < Date.now()) return null;

        if (!payload.id || typeof payload.id !== "number") return null;
        if (!payload.username || typeof payload.username !== "string") return null;

        return payload;
      } catch {
        return null;
      }
    }

    async function getUserFromRequest(req) {
      const token = parseTokenFromRequest(req);
      if (!token) return null;

      // Always look up is_admin from DB (don’t trust token for that)
      const user = await env.DB.prepare(
        "SELECT id, username, is_admin FROM users WHERE id = ?"
      )
        .bind(token.id)
        .first();

      if (!user) return null;
      return { id: user.id, username: user.username, is_admin: !!user.is_admin };
    }

    async function requireUser(req) {
      const user = await getUserFromRequest(req);
      if (!user) return { error: text("Unauthorized", 401), user: null };
      return { error: null, user };
    }

    async function requireAdmin(req) {
      const { error, user } = await requireUser(req);
      if (error) return { error, user: null };
      if (!user.is_admin) return { error: text("Unauthorized", 401), user: null };
      return { error: null, user };
    }

    // ---------------- EMAIL ----------------
    async function sendEmail(subject, html) {
      if (!env.RESEND_API_KEY) { console.error("EMAIL: RESEND_API_KEY not set"); return; }
      if (!env.NOTIFY_EMAIL)   { console.error("EMAIL: NOTIFY_EMAIL not set"); return; }
      try {
        const res = await fetch("https://api.resend.com/emails", {
          method: "POST",
          headers: {
            "Authorization": `Bearer ${env.RESEND_API_KEY}`,
            "Content-Type": "application/json"
          },
          body: JSON.stringify({
            from: "SiKKMiXX <notifications@sikkmixx.com>",
            to: [env.NOTIFY_EMAIL],
            subject,
            html
          })
        });
        const body = await res.json();
        if (!res.ok) {
          console.error("EMAIL failed:", res.status, JSON.stringify(body));
        } else {
          console.log("EMAIL sent:", body.id);
        }
      } catch (e) {
        console.error("EMAIL exception:", e.message);
      }
    }

    async function hashPassword(password) {
      const encoder = new TextEncoder();
      const data = encoder.encode(password);
      const hashBuffer = await crypto.subtle.digest("SHA-256", data);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
    }

    // ---------------- REGISTER ----------------
    if (url.pathname === "/register" && request.method === "POST") {
      try {
        const { username, password } = await request.json();

        if (!username || !password) {
          return json({ error: "Username and password required" }, 400);
        }
        if (password.length < 6) {
          return json({ error: "Password must be at least 6 characters" }, 400);
        }

        const existing = await env.DB.prepare(
          "SELECT id FROM users WHERE username = ?"
        )
          .bind(username)
          .first();

        if (existing) {
          return json({ error: "Username already exists" }, 409);
        }

        const hashed = await hashPassword(password);

        // Note: ensure users table has is_admin default 0
        await env.DB.prepare(
          "INSERT INTO users (username, password) VALUES (?, ?)"
        )
          .bind(username, hashed)
          .run();

        await sendEmail(
          `🎤 New SiKKMiXX Registration: @${username}`,
          `<h2>New user registered</h2>
           <p><strong>Username:</strong> @${username}</p>
           <p><strong>Time:</strong> ${new Date().toUTCString()}</p>`
        );

        return json({ success: true });
      } catch {
        return json({ error: "Server error" }, 500);
      }
    }

    // ---------------- LOGIN ----------------
    if (url.pathname === "/login" && request.method === "POST") {
      try {
        const { username, password } = await request.json();
        const hashed = await hashPassword(password);

        const user = await env.DB.prepare(
          "SELECT id, username FROM users WHERE username = ? AND password = ?"
        )
          .bind(username, hashed)
          .first();

        if (!user) {
          return text("Invalid credentials", 401);
        }

        const token = btoa(
          JSON.stringify({
            id: user.id,
            username: user.username,
            exp: Date.now() + 1000 * 60 * 60, // 1 hour
          })
        );

        return json({ token });
      } catch {
        return text("Server error", 500);
      }
    }

 // ---------------- RESET PASSWORD ----------------
    if (url.pathname === "/reset-password" && request.method === "POST") {
      try {
        const { username, secret, new_password } = await request.json();

        if (!username || !secret || !new_password) {
          return json({ error: "Missing fields" }, 400);
        }
        if (secret !== "skkmxx") {
          return json({ error: "Invalid secret" }, 403);
        }
        if (new_password.length < 6) {
          return json({ error: "Password must be at least 6 characters" }, 400);
        }

        const user = await env.DB.prepare(
          "SELECT id FROM users WHERE username = ?"
        ).bind(username).first();

        if (!user) {
          return json({ error: "User not found" }, 404);
        }

        const hashed = await hashPassword(new_password);
        await env.DB.prepare(
          "UPDATE users SET password = ? WHERE id = ?"
        ).bind(hashed, user.id).run();

        return json({ success: true });
      } catch {
        return json({ error: "Server error" }, 500);
      }
    }

 // ---------------- UPLOAD (SUBMISSION) ----------------
if (url.pathname === "/upload" && request.method === "POST") {
  const { error, user } = await requireUser(request);
  if (error) return error;

  const formData = await request.formData();
  const file = formData.get("file");

  const genre = (formData.get("genre") || "").toString().trim();
  const note = (formData.get("note") || "").toString().trim();
  const artist = (formData.get("artist") || "").toString().trim(); 

  if (!file) return text("No file", 400);

  const validTypes = ["audio/mpeg", "audio/mp3", "audio/wav", "audio/ogg", "audio/x-wav", "audio/flac", "audio/x-m4a"];
  if (!validTypes.includes(file.type)) return text("Only audio files allowed", 400);

  if (file.size > 100 * 1024 * 1024) return text("File too large", 400);

  const id = crypto.randomUUID();
  const safeOriginal = (file.name || "upload.mp3").replace(/[^\w.\- ]+/g, "");
  const isAdmin = !!user.is_admin;
  const key = isAdmin ? `tracks/${id}-${safeOriginal}` : `pending/${id}-${safeOriginal}`;
  const status = isAdmin ? "approved" : "pending";

  await env.MEDIA.put(key, await file.arrayBuffer(), {
    httpMetadata: { contentType: file.type || "application/octet-stream" },
  });

  await env.DB.prepare(
    `INSERT INTO tracks (user_id, filename, original_name, status, genre, note, artist)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(user.id, key, file.name || safeOriginal, status, genre, note, artist)
    .run();

  if (!isAdmin) {
    await sendEmail(
      `🎵 New SiKKMiXX Upload: ${artist ? artist + " — " : ""}${file.name || safeOriginal}`,
      `<h2>New track submitted for review</h2>
       <p><strong>Submitted by:</strong> @${user.username}</p>
       <p><strong>File:</strong> ${file.name || safeOriginal}</p>
       ${artist ? `<p><strong>Artist:</strong> ${artist}</p>` : ""}
       ${genre  ? `<p><strong>Genre:</strong> ${genre}</p>`   : ""}
       ${note   ? `<p><strong>Note:</strong> ${note}</p>`     : ""}
       <p><strong>Time:</strong> ${new Date().toUTCString()}</p>
       <p><a href="https://sikkmixx.com/admin.html">Review in admin panel →</a></p>`
    );
  }

  return json({ success: true, key });
}

    // ---------------- ADMIN: LIST PENDING ----------------
    if (url.pathname === "/admin/pending" && request.method === "GET") {
      const { error } = await requireAdmin(request);
      if (error) return error;

      const { results } = await env.DB.prepare(
        `SELECT id, user_id, filename, original_name, artist, genre, note, uploaded_at
FROM tracks
WHERE status = 'pending'
ORDER BY uploaded_at DESC
`
      ).all();

      return json(results);
    }
	
	// ----Keep /login returning only { token }. Then your login page calls /ME with the token; Worker looks up the user in D1 and returns { id, username, is_admin }.--------------
	
	if (url.pathname === "/me" && request.method === "GET") {
  const { error, user } = await requireUser(request);
  if (error) return error;
  return json({ id: user.id, username: user.username, is_admin: user.is_admin });
}
	
	// ---------------- MY SUBMISSIONS (behind AUTH) ----------------
if (url.pathname === "/my-tracks" && request.method === "GET") {
  const { error, user } = await requireUser(request);
  if (error) return error;

  const { results } = await env.DB.prepare(
    `SELECT id, filename, original_name, artist, status, genre, note, uploaded_at, play_count
FROM tracks
WHERE user_id = ?
ORDER BY uploaded_at DESC
`
  ).bind(user.id).all();

  return json(results);
}

	// ---------------- USER DELETE OWN TRACK ----------------
if (url.pathname === "/my-tracks/delete" && request.method === "POST") {
  const { error, user } = await requireUser(request);
  if (error) return error;

  const { id } = await request.json();
  if (!id) return text("Missing id", 400);

  const track = await env.DB.prepare(
    "SELECT * FROM tracks WHERE id = ? AND user_id = ?"
  ).bind(id, user.id).first();

  if (!track) return text("Not found", 404);

  try { await env.MEDIA.delete(track.filename); } catch {}
  await env.DB.prepare("DELETE FROM tracks WHERE id = ?").bind(id).run();

  return json({ success: true });
}

	

    // ---------------- ADMIN: APPROVE ----------------
    if (url.pathname === "/admin/approve" && request.method === "POST") {
      const { error } = await requireAdmin(request);
      if (error) return error;

      const { id } = await request.json();
      if (!id) return text("Missing id", 400);

      const track = await env.DB.prepare(
        "SELECT * FROM tracks WHERE id = ? AND status = 'pending'"
      )
        .bind(id)
        .first();

      if (!track) return text("Not found", 404);

      const newKey = track.filename.replace(/^pending\//, "tracks/");

      const obj = await env.MEDIA.get(track.filename);
      if (!obj) return text("R2 object missing", 404);

      await env.MEDIA.put(newKey, obj.body, {
        httpMetadata: obj.httpMetadata,
      });

      await env.MEDIA.delete(track.filename);

      await env.DB.prepare(
        "UPDATE tracks SET filename = ?, status = 'approved' WHERE id = ?"
      )
        .bind(newKey, id)
        .run();

      return json({ success: true });
    }

    // ---------------- ADMIN: DELETE (any status) ----------------
    if (url.pathname === "/admin/delete" && request.method === "POST") {
      const { error } = await requireAdmin(request);
      if (error) return error;

      const { id } = await request.json();
      if (!id) return text("Missing id", 400);

      const track = await env.DB.prepare("SELECT * FROM tracks WHERE id = ?")
        .bind(id)
        .first();

      if (!track) return text("Not found", 404);

      // Try delete R2 (ignore if missing)
      try {
        await env.MEDIA.delete(track.filename);
      } catch {}

      await env.DB.prepare("DELETE FROM tracks WHERE id = ?").bind(id).run();

      return json({ success: true });
    }

    // ---------------- PUBLIC: APPROVED TRACKS ONLY ----------------
    if (url.pathname === "/public-tracks" && request.method === "GET") {
      const { results } = await env.DB.prepare(
        `SELECT t.id, t.filename, t.original_name, t.artist, t.genre, t.note, t.uploaded_at, t.play_count, t.vote_count, u.username
FROM tracks t
LEFT JOIN users u ON t.user_id = u.id
WHERE t.status = 'approved'
ORDER BY t.uploaded_at DESC`
      ).all();

      return json(results);
    }
	
// ---------------- TOP SUBMITTERS ----------------
if (url.pathname === "/top-submitters" && request.method === "GET") {
  const { results } = await env.DB.prepare(`
    SELECT u.username, COUNT(*) as track_count
    FROM tracks t
    JOIN users u ON t.user_id = u.id
    WHERE t.status = 'approved'
    GROUP BY t.user_id, u.username
    ORDER BY track_count DESC
    LIMIT 5
  `).all();

  return json(results);
}

// ---------------- LISTENING HEARTBEAT ----------------
if (url.pathname === "/listening" && request.method === "POST") {
  try {
    const { session_id, username, track_name } = await request.json();
    if (!session_id) return text("Missing session_id", 400);

    const now = Date.now();

    await env.DB.prepare(`
      INSERT INTO listeners (session_id, username, track_name, last_seen)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(session_id) DO UPDATE SET
        username = excluded.username,
        track_name = excluded.track_name,
        last_seen = excluded.last_seen
    `).bind(session_id, username || "Guest", track_name || "", now).run();

    // Clean up anyone gone for more than 60s
    await env.DB.prepare(
      "DELETE FROM listeners WHERE last_seen < ?"
    ).bind(now - 60000).run();

    return json({ success: true });
  } catch (e) {
    return text("Server error", 500);
  }
}

// ---------------- GET LISTENERS ----------------
if (url.pathname === "/listeners" && request.method === "GET") {
  try {
    const now = Date.now();
    const { results } = await env.DB.prepare(
      "SELECT username, track_name FROM listeners WHERE last_seen > ? ORDER BY last_seen DESC"
    ).bind(now - 30000).all();

    return json(results);
  } catch (e) {
    return text("Server error", 500);
  }
}

// ---------------- UPVOTE ----------------
if (url.pathname === "/vote" && request.method === "POST") {
  const { error, user } = await requireUser(request);
  if (error) return error;

  const { track_id } = await request.json();
  if (!track_id) return text("Missing track_id", 400);

  const existing = await env.DB.prepare(
    "SELECT 1 FROM votes WHERE user_id = ? AND track_id = ?"
  ).bind(user.id, track_id).first();

  if (existing) {
    // Un-vote
    await env.DB.prepare(
      "DELETE FROM votes WHERE user_id = ? AND track_id = ?"
    ).bind(user.id, track_id).run();
    await env.DB.prepare(
      "UPDATE tracks SET vote_count = MAX(0, COALESCE(vote_count, 0) - 1) WHERE id = ?"
    ).bind(track_id).run();
    return json({ voted: false });
  } else {
    // Vote
    await env.DB.prepare(
      "INSERT INTO votes (user_id, track_id) VALUES (?, ?)"
    ).bind(user.id, track_id).run();
    await env.DB.prepare(
      "UPDATE tracks SET vote_count = COALESCE(vote_count, 0) + 1 WHERE id = ?"
    ).bind(track_id).run();
    return json({ voted: true });
  }
}

// ---------------- MY VOTES ----------------
if (url.pathname === "/my-votes" && request.method === "GET") {
  const { error, user } = await requireUser(request);
  if (error) return error;

  const { results } = await env.DB.prepare(
    "SELECT track_id FROM votes WHERE user_id = ?"
  ).bind(user.id).all();

  return json(results.map(r => r.track_id));
}

// ---------------- INCREMENT PLAY COUNT ----------------
if (url.pathname === "/track-played" && request.method === "POST") {
  try {
    const { id } = await request.json();
    if (!id) return text("Missing id", 400);

    // Increment safely
    await env.DB.prepare(
      "UPDATE tracks SET play_count = COALESCE(play_count, 0) + 1 WHERE id = ? AND status = 'approved'"
    ).bind(id).run();

    return json({ success: true });
  } catch (e) {
    return text("Server error", 500);
  }
}
	

    // ---------------- FILE SERVE ----------------
    if (url.pathname.startsWith("/file/") && request.method === "GET") {
      const key = decodeURIComponent(url.pathname.replace("/file/", ""));

      // Pass Range header to R2 for native range request support
      const obj = await env.MEDIA.get(key, { range: request.headers });

      if (!obj) return text("Not found", 404);

      let contentType = obj.httpMetadata?.contentType || "application/octet-stream";

      // Normalize M4A — browsers store as audio/x-m4a but iOS needs audio/mp4
      if (key.endsWith(".m4a") || contentType === "audio/x-m4a") {
        contentType = "audio/mp4";
      }

      const headers = {
        ...corsHeaders,
        "Content-Type": contentType,
        "Accept-Ranges": "bytes",
      };

      if (obj.range) {
        const { offset, length } = obj.range;
        headers["Content-Range"] = `bytes ${offset}-${offset + length - 1}/${obj.size}`;
        headers["Content-Length"] = String(length);
        return new Response(obj.body, { status: 206, headers });
      }

      if (obj.size !== undefined) {
        headers["Content-Length"] = String(obj.size);
      }

      return new Response(obj.body, { status: 200, headers });
    }

    return text("Not found", 404);
  },
};
