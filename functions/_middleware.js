const PASSWORD = "founderpathwidelab123!";
const COOKIE_NAME = "fp_auth";
const COOKIE_MAX_AGE = 60 * 60 * 24 * 7; // 7 days

async function hash(str) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
}

const LOGIN_HTML = (error = false) => `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Protected — FounderPath</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      background: #0a0a0a;
      font-family: -apple-system, BlinkMacSystemFont, "Inter", sans-serif;
    }
    .card {
      background: #111;
      border: 1px solid #222;
      border-radius: 16px;
      padding: 40px;
      width: 100%;
      max-width: 380px;
    }
    .logo {
      display: block;
      margin: 0 auto 32px;
      height: 28px;
    }
    h1 {
      color: #fff;
      font-size: 18px;
      font-weight: 600;
      text-align: center;
      margin-bottom: 8px;
    }
    p {
      color: #666;
      font-size: 14px;
      text-align: center;
      margin-bottom: 28px;
    }
    input {
      width: 100%;
      padding: 12px 16px;
      background: #1a1a1a;
      border: 1px solid ${error ? "#ef4444" : "#2a2a2a"};
      border-radius: 10px;
      color: #fff;
      font-size: 15px;
      outline: none;
      transition: border-color 0.15s;
      margin-bottom: ${error ? "8px" : "16px"};
    }
    input:focus { border-color: #4f7dff; }
    .error {
      color: #ef4444;
      font-size: 13px;
      margin-bottom: 14px;
      text-align: center;
    }
    button {
      width: 100%;
      padding: 12px;
      background: #4f7dff;
      border: none;
      border-radius: 10px;
      color: #fff;
      font-size: 15px;
      font-weight: 600;
      cursor: pointer;
      transition: opacity 0.15s;
    }
    button:hover { opacity: 0.88; }
  </style>
</head>
<body>
  <div class="card">
    <svg class="logo" viewBox="0 0 140 28" fill="none" xmlns="http://www.w3.org/2000/svg">
      <text x="0" y="22" font-family="Inter,sans-serif" font-size="20" font-weight="700" fill="white">FounderPath</text>
    </svg>
    <h1>Protected page</h1>
    <p>Enter the password to continue</p>
    <form method="POST">
      <input type="password" name="password" placeholder="Password" autofocus />
      ${error ? '<p class="error">Incorrect password, try again.</p>' : ""}
      <button type="submit">Continue</button>
    </form>
  </div>
</body>
</html>`;

export async function onRequest(context) {
  const { request, next } = context;
  const url = new URL(request.url);

  const expectedHash = await hash(PASSWORD);

  // Check cookie
  const cookies = request.headers.get("cookie") || "";
  const authCookie = cookies.split(";").find(c => c.trim().startsWith(COOKIE_NAME + "="));
  const cookieValue = authCookie ? authCookie.split("=")[1].trim() : null;

  if (cookieValue === expectedHash) {
    return next();
  }

  // Handle login POST
  if (request.method === "POST") {
    const formData = await request.formData();
    const submitted = formData.get("password") || "";

    if (submitted === PASSWORD) {
      const response = new Response(null, {
        status: 302,
        headers: {
          "Location": url.pathname,
          "Set-Cookie": `${COOKIE_NAME}=${expectedHash}; Path=/; Max-Age=${COOKIE_MAX_AGE}; HttpOnly; SameSite=Lax; Secure`,
        },
      });
      return response;
    }

    return new Response(LOGIN_HTML(true), {
      status: 401,
      headers: { "Content-Type": "text/html; charset=utf-8" },
    });
  }

  return new Response(LOGIN_HTML(false), {
    status: 200,
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}
