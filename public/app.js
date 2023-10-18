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

  const isValidToken = () => {
    const expirationDate = localStorage.getItem("creation_date") || null;
    if (!expirationDate) {
      return true;
    }
    return expirationDate < new Date();
  }

  const updateOAuthInfo = (access_token, refresh_token, expires_in) => {
    return `
    <h2>oAuth info</h2>
    <table>
      <tr>
        <td>Access token</td>
        <td>${access_token}</td>
      </tr>
      <tr>
        <td>Refresh token</td>
        <td>${refresh_token}</td>
      </tr>
      <tr>
        <td>Expiration at</td>
        <td>${getExpirationDate(expires_in)}</td>
      </tr>
    </table>`
  }

  const updateUserData = (data) => {
    return `
    <h1>Logged in as ${data.display_name}</h1>
    <img width="150" src="${data.images[0].url}" alt="${data.display_name}" />
    <table>
      <tr>
        <td>Display name</td>
        <td>${data.display_name}</td>
      </tr>
      <tr>
        <td>Id</td>
        <td>${data.id}</td>
      </tr>
      <tr>
        <td>Email</td>
        <td>${data.email}</td>
      </tr>
      <tr>
        <td>Spotify URI</td>
        <td>
          <a href="${data.external_urls.spotify}">${data.external_urls.spotify}</a>
        </td>
      </tr>
      <tr>
        <td>Link </dt>
        <td>
          <a href="${data.href}">${data.href}</a>
        </td>
      </tr>
      <tr>
        <td>Profile Image</td>
        <td>
          <a href="${data.images[0].url}">${data.images[0].url}}</a>
        </td>
      </tr>
      <tr>
        <td>Country</td>
        <td>${data.country}</td>
      </tr>
    </table>`
  }

  /* oAuth2 PKCE helpers */
  function generateRandomString() {
    const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const values = crypto.getRandomValues(new Uint8Array(64));
    return values.reduce((acc, x) => acc + possible[x % possible.length], "");
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
    window.location.href = redirectUri;
  }

  /* return token from a given authorize code */
  const getToken = async code => {
    const codeVerifier = localStorage.getItem('code_verifier');

    const payload = {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        client_id: clientId,
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri,
        code_verifier: codeVerifier,
      }),
    }

    const response = await doAPIcall(tokenEndpoint, payload);
    updateToken(response);
  }

  const getRefreshToken = async () => {
    const refreshToken = localStorage.getItem('refresh_token');

    const payload = {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        client_id: clientId,
        grant_type: 'refresh_token',
        refresh_token: refreshToken
      }),
    }
    const response = await doAPIcall(tokenEndpoint, payload);
    updateToken(response);
  }

  const updateToken = (response) => {
    accessToken = response.access_token;
    refreshToken = response.refresh_token;
    expiresIn = response.expires_in;

    localStorage.setItem('access_token', accessToken);
    localStorage.setItem('refresh_token', refreshToken);
    localStorage.setItem('creation_date', new Date());
    localStorage.setItem('expires_in', expiresIn);

    // update oauth UI
    document.getElementById('oauth').innerHTML = updateOAuthInfo(accessToken, refreshToken, expiresIn);
  }


  /* request a new authorization code */
  const generateCode = async() => {
    const codeVerifier  = generateRandomString();
    const hashed = await sha256(codeVerifier)
    const codeChallenge = base64URLEncode(hashed);

    window.localStorage.setItem('code_verifier', codeVerifier);

    const authUrl = new URL(authorizationEndpoint)
    const params =  {
      response_type: 'code',
      client_id: clientId,
      scope,
      code_challenge_method: codeChallengeMethod,
      code_challenge: codeChallenge,
      redirect_uri: redirectUri,
    }

    authUrl.search = new URLSearchParams(params).toString();

    // Redirect the user to the authorization server for login
    window.location.href = authUrl.toString();
  }

  /* API call to /me endpoint */
  const getUserData = async () => {
    let accessToken = localStorage.getItem('access_token');
    const payload = {
      method: 'GET',
      headers: {
        'Authorization': 'Bearer ' + accessToken,
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

  document.getElementById('refresh-token-button').addEventListener('click', () => {
    getRefreshToken();
  });

  // app configuration
  const clientId = 'yourclientid'; // your clientID
  const redirectUri = 'http://your-redirect-uri'; // your redirect URI

  // OAuth2 configuration
  const hostname = "https://accounts.spotify.com";
  const authorizationEndpoint = `${hostname}/authorize`;
  const tokenEndpoint = `${hostname}/api/token`;
  const scope = 'user-read-private user-read-email';
  const codeChallengeMethod = 'S256';

  let accessToken = localStorage.getItem('access_token') || null;
  let refreshToken = localStorage.getItem('refresh_token') || null;
  let expiresIn = localStorage.getItem('refresh_in') || null;

  // Try to fetch auth code from current browser search URL
  const args = new URLSearchParams(window.location.search);
  const code = args.get('code');

  if (code) {
    if (!accessToken || !isValidToken()) {
      await getToken(code);
    }

    // request user info and update UI
    getUserData();

    loginSection.style.display = 'none';
    dataSection.style.display = 'unset';
  }
})();

