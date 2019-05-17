# obelisk-oauth

## Setup

This repo contains two packages: obelisk-oauth-common and obelisk-oauth-backend.

To add these packages to your obelisk project, follow the steps below from your obelisk project root (i.e., the folder you ran `ob init` in).

### Add dependency thunk
```bash
$ mkdir dep
$ cd dep
$ git clone git@github.com:obsidian.systems/obelisk-oauth
$ ob thunk pack obelisk-oauth
```

The last step here (`ob thunk pack`) replaces the cloned repository with a "thunk" that contains all the information obelisk needs to fetch/use the repository when needed. You should now see the following if you run `tree` from the `dep` folder.

```bash
$ tree
.
└── obelisk-oauth
    ├── default.nix
    └── github.json
```

Check out `ob thunk --help` to learn more about working with thunks.

### Add packages to default.nix

Your skeleton project's `default.nix` uses the [reflex-platform project infrastructure](https://github.com/reflex-frp/reflex-platform/blob/develop/project/default.nix). We can use the [`packages` field](https://github.com/reflex-frp/reflex-platform/blob/develop/project/default.nix#L53-L58) of the project configuration to add our custom packages, as follows:

```nix
project ./. ({ hackGet, ... }: {
  packages = {
    obelisk-oauth-common = (hackGet ./dep/obelisk-oauth) + "/common";
    obelisk-oauth-backend = (hackGet ./dep/obelisk-oauth) + "/backend";
    ... # other configuration goes here
  };
})
```

Be sure to add `hackGet` to the list of items to bring into scope. `hackGet` is a nix function defined in reflex-platform that takes a path that points to either a source directory or a packed thunk (in other words, it takes a path to a thunk but doesn't care whether it's packed or unpacked). It produces a path to the source (unpacked if necessary). Once we've got that path, we just need to append the subdirectory paths to the individual repos contained in this repository.

### Add packages to cabal files

Finally, add `obelisk-oauth-common` to the `build-depends` field of `common/common.cabal` and add `obelisk-oauth-backend` to the `build-depends` field of the library stanza in `backend/backend.cabal`.

## Common.Route + Obelisk.OAuth.Authorization

Add a sub-route to your backend route and embed the provided OAuth route:

```haskell
data BackendRoute :: * -> * where
  BackendRoute_Missing :: BackendRoute ()
  BackendRoute_Api :: BackendRoute ()
  BackendRoute_OAuth :: BackendRoute (R OAuth)
```

Your backend route encoder should handle this case:
```haskell
  ...
  pathComponentEncoder $ \case
    BackendRoute_OAuth -> PathSegment "oauth" oauthRouteEncoder
  ...
```

## Frontend

On the frontend, you need to produce an authorization request link with the appropriate callback embedded.

For example:

```haskell
do
  let r = AuthorizationRequest
        { _authorizationRequest_responseType = AuthorizationResponseType_Code
        , _authorizationRequest_clientId = clientId
        , _authorizationRequest_redirectUri = Just BackendRoute_OAuth
        , _authorizationRequest_scope = []
        , _authorizationRequest_state = Just "none"
        }
      grantHref = authorizationRequestHref "https://app.asana.com/-/oauth_authorize" route checkedEncoder r
  elAttr "a" ("href" =: grantHref) $ text "Authorize with Asana"
```

## Backend

In your backend handler, you'll need to handle the OAuth sub-route you created:

```haskell
...
serve $ \case
  BackendRoute_OAuth :/ oauthRoute -> case oauthRoute of
    OAuth_RedirectUri :/ redirectParams -> case params of
      Nothing -> liftIO $ error "Expected to receive the authorization code here"
      Just (RedirectUriParams code mstate) -> do
        let t = TokenRequest
              { _tokenRequest_grant = TokenGrant_AuthorizationCode $ T.encodeUtf8 code
              , _tokenRequest_clientId = clientId -- Get this from the OAuth authorization server
              , _tokenRequest_clientSecret = clientSecret -- Get this from the OAuth authorization server
              , _tokenRequest_redirectUri = BackendRoute_OAuth
              }
            reqUrl = "https://app.asana.com/-/oauth_token"
        rsp <- liftIO $ flip httpLbs tlsMgr =<< getOauthToken reqUrl route checkedEncoder t
        -- ^ this response should include the access token and probably a refresh token
...
```
