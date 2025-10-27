/**
 * Cloudflare Worker for CF_Authorization IP validation.
 *
 * This Worker extracts the CF_Authorization cookie, uses it to fetch
 * the identity (which contains the IP claim) from the Access endpoint,
 * and compares that IP claim to the client's connecting IP (CF-Connecting-IP).
 * If they don't match, it returns a 403 Forbidden response.
 *
 * 
 */

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
  const url = new URL(request.url);
  const hostname = url.hostname; // Automatically gets the hostname from the request

  // 1. Get the CF_Authorization cookie value
  const cookieHeader = request.headers.get('Cookie');
  if (!cookieHeader) {
    // If no cookies are present, we probably shouldn't proceed, but
    // a proper Access setup should handle the initial redirect/auth.
    // For this validation step, we'll assume it should be present.
    return new Response('Forbidden', { status: 403 });
  }

  const cookies = parseCookies(cookieHeader);
  const cfAuthCookie = cookies['CF_Authorization'];

  if (!cfAuthCookie) {
    return new Response('Forbidden', { status: 403 });
  }

  // 2. Get the client's connecting IP
  const clientIP = request.headers.get('CF-Connecting-IP');
  if (!clientIP) {
    // This header is generally reliable on Cloudflare, but good to check.
    return new Response('Forbidden', { status: 403 });
  }

  // 3. Lookup identity using the CF_Authorization cookie
  const identityUrl = `https://${hostname}/cdn-cgi/access/get-identity`;
  
  // Create headers for the identity request, including the CF_Authorization cookie
  const identityHeaders = new Headers();
  identityHeaders.append('Cookie', `CF_Authorization=${cfAuthCookie}`);

  try {
    const identityResponse = await fetch(identityUrl, {
      method: 'GET',
      headers: identityHeaders,
    });

    if (!identityResponse.ok) {
      // Identity lookup failed (e.g., cookie expired or invalid)
      // Pass-through the response status from the identity endpoint for debugging/info
      console.log(`Identity lookup failed with status: ${identityResponse.status}`);
      return new Response('Forbidden', { status: 403 });
    }

    const identityData = await identityResponse.json();
    
    // 4. Get the value of the 'ip' claim
    const identityIP = identityData.ip;

    if (!identityIP) {
      console.log('Identity response missing ip claim');
      return new Response('Forbidden', { status: 403 });
    }

    // 5. Compare the IPs
    if (clientIP === identityIP) {
      // IPs match: Allow the request to proceed to the origin
      return fetch(request);
    } else {
      // IPs do not match: Respond with Forbidden
      console.log(`IP mismatch: Client IP (${clientIP}) vs Identity IP (${identityIP})`);
      return new Response('Forbidden)', { status: 403 });
    }

  } catch (error) {
    console.error('Worker error during identity check:', error);
    return new Response('Internal Server Error', { status: 500 });
  }
}

/**
 * Helper function to parse the Cookie header string into a key-value object.
 * @param {string} cookieHeader The value of the 'Cookie' request header.
 * @returns {Object} An object mapping cookie names to their values.
 */
function parseCookies(cookieHeader) {
  const cookies = {};
  if (cookieHeader) {
    cookieHeader.split(';').forEach(cookie => {
      const parts = cookie.trim().split('=');
      const name = parts[0];
      const value = parts.slice(1).join('=');
      if (name) {
        cookies[name] = value;
      }
    });
  }
  return cookies;
}
