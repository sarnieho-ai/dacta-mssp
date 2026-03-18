// Vercel Serverless Function — User Administration API
// Handles auth account creation, password reset via Supabase Admin API.
// Service role key stays server-side — never exposed to browser.

const { SUPABASE_URL, sbHeaders, sbFetch, SUPABASE_SECRET_KEY } = require('./lib/supabase');
const { setCors, requireAuth } = require('./lib/auth');

// Generate a secure random temporary password
function generateTempPassword() {
  const upper = 'ABCDEFGHJKMNPQRSTUVWXYZ';
  const lower = 'abcdefghjkmnpqrstuvwxyz';
  const digits = '23456789';
  const special = '!@#$%&*';
  const all = upper + lower + digits + special;

  // Ensure at least one of each category
  let pw = '';
  pw += upper[Math.floor(Math.random() * upper.length)];
  pw += lower[Math.floor(Math.random() * lower.length)];
  pw += digits[Math.floor(Math.random() * digits.length)];
  pw += special[Math.floor(Math.random() * special.length)];

  // Fill remaining 8 chars
  for (let i = 0; i < 8; i++) {
    pw += all[Math.floor(Math.random() * all.length)];
  }

  // Shuffle
  return pw.split('').sort(() => Math.random() - 0.5).join('');
}

export default async function handler(req, res) {
  setCors(req, res);
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  // SECURITY: Require authenticated session for all user admin operations
  const authUser = await requireAuth(req, res);
  if (!authUser) return; // 401 already sent

  if (!SUPABASE_SECRET_KEY) {
    return res.status(500).json({ error: 'Service key not configured' });
  }

  const { action, email, display_name, password } = req.body || {};

  // ── ACTION: create-user ──
  // Creates a Supabase auth user with a temporary password
  if (action === 'create-user') {
    if (!email) return res.status(400).json({ error: 'Email is required' });

    const tempPassword = password || generateTempPassword();

    try {
      // Check if auth user already exists
      const listResp = await fetch(`${SUPABASE_URL}/auth/v1/admin/users?per_page=50`, {
        headers: {
          'apikey': SUPABASE_SECRET_KEY,
          'Authorization': `Bearer ${SUPABASE_SECRET_KEY}`,
        },
      });
      const listData = await listResp.json();
      const existing = (listData.users || []).find(u => u.email && u.email.toLowerCase() === email.toLowerCase());

      if (existing) {
        return res.status(409).json({
          error: 'Auth account already exists for this email',
          auth_uid: existing.id,
        });
      }

      // Create auth user via Supabase Admin API
      const createResp = await fetch(`${SUPABASE_URL}/auth/v1/admin/users`, {
        method: 'POST',
        headers: {
          'apikey': SUPABASE_SECRET_KEY,
          'Authorization': `Bearer ${SUPABASE_SECRET_KEY}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          email: email,
          password: tempPassword,
          email_confirm: true,  // Auto-confirm so they can log in immediately
          user_metadata: {
            display_name: display_name || email.split('@')[0],
          },
        }),
      });

      const createData = await createResp.json();

      if (!createResp.ok) {
        return res.status(createResp.status).json({
          error: createData.msg || createData.message || 'Failed to create auth user',
          details: createData,
        });
      }

      return res.status(200).json({
        success: true,
        auth_uid: createData.id,
        email: email,
        temp_password: tempPassword,
      });

    } catch (err) {
      return res.status(500).json({ error: 'Server error: ' + err.message });
    }
  }

  // ── ACTION: reset-password ──
  // Resets a user's password to a new temporary password
  if (action === 'reset-password') {
    if (!email) return res.status(400).json({ error: 'Email is required' });

    const newPassword = password || generateTempPassword();

    try {
      // Find the auth user by email
      const listResp = await fetch(`${SUPABASE_URL}/auth/v1/admin/users?per_page=50`, {
        headers: {
          'apikey': SUPABASE_SECRET_KEY,
          'Authorization': `Bearer ${SUPABASE_SECRET_KEY}`,
        },
      });
      const listData = await listResp.json();
      const user = (listData.users || []).find(u => u.email && u.email.toLowerCase() === email.toLowerCase());

      if (!user) {
        return res.status(404).json({ error: 'No auth account found for this email' });
      }

      // Update password via Admin API
      const updateResp = await fetch(`${SUPABASE_URL}/auth/v1/admin/users/${user.id}`, {
        method: 'PUT',
        headers: {
          'apikey': SUPABASE_SECRET_KEY,
          'Authorization': `Bearer ${SUPABASE_SECRET_KEY}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          password: newPassword,
        }),
      });

      const updateData = await updateResp.json();

      if (!updateResp.ok) {
        return res.status(updateResp.status).json({
          error: updateData.msg || updateData.message || 'Failed to reset password',
        });
      }

      return res.status(200).json({
        success: true,
        email: email,
        temp_password: newPassword,
      });

    } catch (err) {
      return res.status(500).json({ error: 'Server error: ' + err.message });
    }
  }

  // ── ACTION: check-auth-status ──
  // Returns which emails have auth accounts
  if (action === 'check-auth-status') {
    try {
      const listResp = await fetch(`${SUPABASE_URL}/auth/v1/admin/users?per_page=50`, {
        headers: {
          'apikey': SUPABASE_SECRET_KEY,
          'Authorization': `Bearer ${SUPABASE_SECRET_KEY}`,
        },
      });
      const listData = await listResp.json();
      const authEmails = (listData.users || []).map(u => ({
        email: (u.email || '').toLowerCase(),
        auth_uid: u.id,
        confirmed: !!u.email_confirmed_at,
        last_sign_in: u.last_sign_in_at || null,
      }));

      return res.status(200).json({ success: true, auth_users: authEmails });

    } catch (err) {
      return res.status(500).json({ error: 'Server error: ' + err.message });
    }
  }

  // ── ACTION: bulk-provision ──
  // Creates auth accounts for multiple emails at once
  if (action === 'bulk-provision') {
    const { users } = req.body || {};
    if (!users || !Array.isArray(users) || users.length === 0) {
      return res.status(400).json({ error: 'users array is required' });
    }

    // First get existing auth users
    let existingEmails = new Set();
    try {
      const listResp = await fetch(`${SUPABASE_URL}/auth/v1/admin/users?per_page=50`, {
        headers: {
          'apikey': SUPABASE_SECRET_KEY,
          'Authorization': `Bearer ${SUPABASE_SECRET_KEY}`,
        },
      });
      const listData = await listResp.json();
      (listData.users || []).forEach(u => {
        if (u.email) existingEmails.add(u.email.toLowerCase());
      });
    } catch (err) {
      return res.status(500).json({ error: 'Failed to check existing users: ' + err.message });
    }

    const results = [];

    for (const u of users) {
      if (!u.email) {
        results.push({ email: u.email, success: false, error: 'No email' });
        continue;
      }
      if (existingEmails.has(u.email.toLowerCase())) {
        results.push({ email: u.email, success: false, error: 'Already provisioned', skipped: true });
        continue;
      }

      const tempPw = generateTempPassword();

      try {
        const createResp = await fetch(`${SUPABASE_URL}/auth/v1/admin/users`, {
          method: 'POST',
          headers: {
            'apikey': SUPABASE_SECRET_KEY,
            'Authorization': `Bearer ${SUPABASE_SECRET_KEY}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            email: u.email,
            password: tempPw,
            email_confirm: true,
            user_metadata: {
              display_name: u.display_name || u.email.split('@')[0],
            },
          }),
        });

        const createData = await createResp.json();

        if (createResp.ok) {
          existingEmails.add(u.email.toLowerCase());
          results.push({ email: u.email, display_name: u.display_name, success: true, temp_password: tempPw });
        } else {
          results.push({ email: u.email, success: false, error: createData.msg || createData.message || 'Creation failed' });
        }
      } catch (err) {
        results.push({ email: u.email, success: false, error: err.message });
      }
    }

    return res.status(200).json({
      success: true,
      provisioned: results.filter(r => r.success).length,
      skipped: results.filter(r => r.skipped).length,
      failed: results.filter(r => !r.success && !r.skipped).length,
      results: results,
    });
  }

  return res.status(400).json({ error: 'Unknown action: ' + action });
}
