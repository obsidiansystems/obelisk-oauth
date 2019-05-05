# obelisk-oauth

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
    OAuth_RedirectUri :/ redirectParams -> case redirectParams of
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
