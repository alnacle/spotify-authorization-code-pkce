/**
 * This is an example of a basic node.js script that performs
 * the Authorization Code with PKCE oAuth2 flow to authenticate 
 * against the Spotify Accounts.
 *
 * For more information, read
 * https://developer.spotify.com/documentation/web-api/tutorials/code-pkce-flow
 */

(async function() {

  const getExpirationDate = (offset) => {
    const d = new Date();
    d.setSeconds(d.getSeconds() + offset);
    return d.toLocaleTimeString()
  }

  const updateOAuthInfo = (access_token, refresh_token, expires_in) => {
    return `<h2>oAuth info</h2>
      <dl class="dl-horizontal">
        <dt>Access token</dt><dd class="text-overflow">${access_token}</dd>
        <dt>Refresh token</dt><dd class="text-overflow">${refresh_token}</dd>
        <dt>Expiration at</dt><dd class="text-overflow">${getExpirationDate(expires_in)}</dd>
      </dl>`;
  }

  const updateUserData = (data) => {
    return `<h1>Logged in as ${data.display_name}</h1>
      <div class="media">
        <div class="pull-left">
          <img class="media-object" width="150" src="${data.images[0].url}" />
        </div>
        <div class="media-body">
          <dl class="dl-horizontal">
            <dt>Display name</dt><dd class="clearfix">${data.display_name}</dd>
            <dt>Id</dt><dd>${data.id}</dd>
            <dt>Email</dt><dd>${data.email}</dd>
            <dt>Spotify URI</dt><dd><a href="${data.external_urls.spotify}">${data.external_urls.spotify}</a></dd>
            <dt>Link</dt><dd><a href="${data.href}">${data.href}</a></dd>
            <dt>Profile Image</dt><dd class="clearfix"><a href="${data.images[0].url}">${data.images[0].url}}</a></dd>
            <dt>Country</dt><dd>${data.country}</dd>
          </dl>
        </div>
      </div>`;
  }

  /* oAuth2 PKCE helpers */
  const generateRandomString = (length) => {
    var array = new Uint32Array(length);
    array = window.crypto.getRandomValues(array);
    return Array.from(array, dec => ('0' + dec.toString(16)).substr(-2)).join('');
  }

  const sha256 = async (plain) => {
    const encoder = new TextEncoder()
    const data = encoder.encode(plain)

    return window.crypto.subtle.digest('SHA-256', data)
  }

  const base64URLEncode = (input) => {
    return btoa(String.fromCharCode(...new Uint8Array(input)))
      .replace(/=/g, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_');
  }

  /* HTTP requests helper */
  const doAPIcall = async (url, payload) => {
    const response = await fetch(url, payload);
    return await response.json();
  }

  /* clean up environment */
  const logout = () => {
    localStorage.clear();
    window.location.href = redirect_uri;
  }

  /* return token from a given authorize code */
  const getToken = async code => {
    const code_verifier = localStorage.getItem('code_verifier');

    const payload = {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        client_id,
        grant_type: 'authorization_code',
        code,
        redirect_uri,
        code_verifier,
      }),
    }

    const response = await doAPIcall(tokenEndpoint, payload)

    access_token = response.access_token;
    refresh_token = response.refresh_token;
    expires_in = response.expires_in;

    localStorage.setItem('access_token', access_token);
    localStorage.setItem('refresh_token', refresh_token);
    localStorage.setItem('expires_in', expires_in);
  }

  /* request a new authorization code */
  const generateCode = async() => {
    const code_verifier  = generateRandomString(32);
    const hashed = await sha256(code_verifier)
    const code_challenge = base64URLEncode(hashed);

    window.localStorage.setItem('code_verifier', code_verifier);

    const authUrl = new URL(authorizationEndpoint)
    const params =  {
      response_type: 'code',
      client_id,
      scope,
      code_challenge_method,
      code_challenge,
      redirect_uri,
    }

    authUrl.search = new URLSearchParams(params).toString();

    // Redirect the user to the authorization server for login
    window.location.href = authUrl.toString();
  }

  /* API call to /me endpoint */
  const getUserData = async () => {
    let access_token = localStorage.getItem('access_token');
    const payload = {
      method: 'GET',
      headers: {
        'Authorization': 'Bearer ' + access_token,
      },
    }
    response = await doAPIcall('https://api.spotify.com/v1/me', payload)
    document.getElementById('user-profile').innerHTML = updateUserData(response);
  }

  /* Fun starts here */

  // UI elements
  const loginSection = document.getElementById('login');
  const dataSection = document.getElementById('loggedin');

  // show login button, hide the rest
  loginSection.style.display = 'unset';
  dataSection.style.display = 'none';

  document.getElementById('login-button').addEventListener('click', () => {
    generateCode();
  });

  document.getElementById('logout-button').addEventListener('click', () => {
    logout();
  });

  // app configuration
  const client_id = ''; // your clientID
  const redirect_uri = ''; // your redirect URI

  // OAuth2 configuration
  const hostname = "https://accounts.spotify.com";
  const authorizationEndpoint = `${hostname}/authorize`;
  const tokenEndpoint = `${hostname}/api/token`;
  const scope = 'user-read-private user-read-email';
  const code_challenge_method = 'S256';

  let access_token = localStorage.getItem('access_token') || null;
  let refresh_token = localStorage.getItem('refresh_token') || null;
  let expires_in = localStorage.getItem('refresh_in') || null;

  // Try to fetch auth code from current browser search URL
  const args = new URLSearchParams(window.location.search);
  const code = args.get('code');

  if (code) {
    loginSection.style.display = 'none';
    dataSection.style.display = 'unset';

    if (!access_token) {
      await getToken(code);
    }

    // update oauth UI
    document.getElementById('oauth').innerHTML = updateOAuthInfo(access_token, refresh_token, expires_in);

    // request user info and update UI
    getUserData();
  }
})();

