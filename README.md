# Spotify Authorization Code with PKCE example

This app displays your Spotify profile information using Authorization Code with PKCE to grant permissions to the app.

## Using your own credentials

You will need to register your app and get your own credentials from the [Spotify for Developers Dashboard](https://developer.spotify.com/dashboard).

- Create a new app in the dashboard and add `http://localhost:8080` to the app's redirect URL list.
- Edit the `public/app.js` file and replace the `client_id` and `redirect_uri` variables with your values.

## Running the example

From a console shell:

    $ npm start

Then, open `http://localhost:8080` in a browser.
