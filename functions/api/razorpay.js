export async function onRequestPost(context) {
  const { request, env } = context;

  // Read the RAW Razorpay webhook body.
  // Razorpay requires the raw body for signature verification.
  const rawBody = await request.text();

  const signature = request.headers.get("X-Razorpay-Signature");

  if (!signature) {
    return new Response("Missing Razorpay signature", { status: 400 });
  }

  // Create HMAC-SHA256 signature using your Cloudflare secret.
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(env.RAZORPAY_WEBHOOK_SECRET),
    {
      name: "HMAC",
      hash: "SHA-256"
    },
    false,
    ["sign"]
  );

  const signatureBuffer = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(rawBody)
  );

  const expectedSignature = Array.from(
    new Uint8Array(signatureBuffer)
  )
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");

  if (signature !== expectedSignature) {
    return new Response("Invalid Razorpay signature", { status: 401 });
  }

  let data;

  try {
    data = JSON.parse(rawBody);
  } catch {
    return new Response("Invalid JSON", { status: 400 });
  }

  // We only process successful Payment Link payments.
  if (data.event !== "payment_link.paid") {
    return new Response("Event ignored", { status: 200 });
  }

  // Razorpay Payment Link payload contains customer information.
  const paymentLink =
    data?.payload?.payment_link?.entity;

  const order =
    data?.payload?.order?.entity;

  const customerEmail =
    paymentLink?.customer?.email ||
    order?.customer_email ||
    order?.email;

  const customerName =
    paymentLink?.customer?.name ||
    "GOAT METHOD Member";

  const paymentLinkId =
    paymentLink?.id || "Unknown";

  const amount =
    paymentLink?.amount_paid ||
    order?.amount_paid ||
    6900;

  if (!customerEmail) {
    return new Response("Customer email not found", {
      status: 400
    });
  }

  // ----------------------------------------------------
  // RESEND
  // ----------------------------------------------------

  const resendResponse = await fetch(
    "https://api.resend.com/emails",
    {
      method: "POST",

      headers: {
        "Authorization": `Bearer ${env.RESEND_API_KEY}`,
        "Content-Type": "application/json"
      },

      body: JSON.stringify({
        from: "GOAT METHOD <onboarding@resend.dev>",
        to: [customerEmail],
        subject: "🔥 GOAT METHOD — Your Access Is Ready",

        html: `
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width">
</head>

<body style="
margin:0;
padding:0;
background:#080808;
font-family:Arial,Helvetica,sans-serif;
color:#ffffff;
">

<div style="
max-width:600px;
margin:auto;
background:#0d0d0d;
padding:40px 25px;
text-align:center;
">

<h1 style="
color:#d6aa45;
letter-spacing:3px;
margin-bottom:5px;
">
GOAT METHOD
</h1>

<p style="
color:#999;
font-size:12px;
letter-spacing:2px;
">
30-DAY PREMIUM FITNESS SYSTEM
</p>

<hr style="
border:0;
border-top:1px solid #292929;
margin:30px 0;
">

<h2 style="font-size:28px;">
Welcome, ${escapeHtml(customerName)} 🔥
</h2>

<p style="
color:#bdbdbd;
font-size:16px;
line-height:1.7;
">
Your GOAT METHOD purchase has been successfully received.
</p>

<div style="
margin:30px 0;
padding:25px;
border:1px solid #3a2b12;
background:#111;
">

<p style="
margin:0 0 10px;
color:#d6aa45;
font-weight:bold;
">
PAYMENT CONFIRMED
</p>

<p style="
margin:0;
color:#aaa;
">
Amount: ₹${(amount / 100).toFixed(2)}
</p>

</div>

<p style="
color:#aaa;
line-height:1.7;
">
Your GOAT METHOD 30-Day Transformation Plan will be delivered
through your secure download access.
</p>

<div style="margin:35px 0;">

<a href="YOUR_EBOOK_DOWNLOAD_LINK"
style="
display:inline-block;
background:#d6aa45;
color:#050505;
text-decoration:none;
padding:16px 28px;
font-weight:bold;
border-radius:5px;
">
ACCESS YOUR GOAT METHOD →
</a>

</div>

<p style="
font-size:12px;
color:#666;
line-height:1.6;
">
Payment Link ID:<br>
${escapeHtml(paymentLinkId)}
</p>

<hr style="
border:0;
border-top:1px solid #222;
margin:30px 0;
">

<p style="
font-size:12px;
color:#666;
">
© 2026 GOAT METHOD. All Rights Reserved.
</p>

</div>

</body>
</html>
`
      })
    }
  );

  if (!resendResponse.ok) {
    const errorText = await resendResponse.text();

    console.error("Resend error:", errorText);

    return new Response("Email sending failed", {
      status: 500
    });
  }

  return new Response(
    JSON.stringify({
      success: true,
      message: "GOAT METHOD payment processed"
    }),
    {
      status: 200,
      headers: {
        "Content-Type": "application/json"
      }
    }
  );
}


// Basic HTML escaping for customer-provided values.
function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
