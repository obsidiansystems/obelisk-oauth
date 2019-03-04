{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeApplications #-}
{-| Creation of the authorization request, targeted at the authorization server, initiated by the frontend.

This module provides the means for easily creating a request to an
authorization server as specified in rfc6749.  More concrete, it provides the
means for creating the URI to the authorization server you are going to
redirect the user to, so he can be prompted for authorization by the resource
server (E.g. github).

This redirect will be issued by the frontend as it has the means to
generate and hold on to the needed `OAuthState` via session storage for
example.
-}
module Obelisk.OAuth.AuthorizationRequest
  ( -- * Types and classes
    AuthorizationResponseType (..)
  , AuthorizationRequest (..)
  , OAuthClientId (..)
  , OAuthState
    -- * Build actual request
  , authorizationRequestHref
    -- * Helper functions
    --
    --   You should usually not need those and be fine with just `authorizationRequestHref`.
  , authorizationRequestParams
  ) where

import Prelude hiding ((.))

import Control.Category ((.))
import Data.Functor.Identity (Identity (..))
import qualified Data.Map as Map
import Data.Text (Text)
import qualified Data.Text as T

import Obelisk.OAuth.Route (OAuthClientId (..), OAuthRoute (..))
import Obelisk.OAuth.State (OAuthState, oAuthStateAsText)
import Obelisk.Route
import Obelisk.OAuth.Config (AuthorizationResponseType (..), OAuthConfig (..), ProviderConfig (..))
import Obelisk.OAuth.Provider

-- | Request going to an authorization server/provider.
data AuthorizationRequest provider = AuthorizationRequest
  { _authorizationRequest_provider :: provider
    -- ^ What provider to send this request too?
  , _authorizationRequest_scope :: [Text]
    -- ^ What oauth scopes we should try to acquire.
    -- <https://tools.ietf.org/html/rfc6749#section-3.3 Section 3.3>.
  }

-- | Render the authorization request.
--
--   This should be all you need from this module in most cases.
authorizationRequestHref
  :: OAuthProvider provider
  => OAuthConfig provider
  -> AuthorizationRequest provider
  -> OAuthState
  -> Text -- ^ Authorization grant request endpoint with query string
authorizationRequestHref cfg req state =
  oAuthAuthorizeEndpoint  (_authorizationRequest_provider req) <> "?" <>
    authorizationRequestParams cfg req state


-- | Turn an 'AuthorizationRequest' into query string parameters separated by
--   @&@. Key names are defined in
--
-- <https://tools.ietf.org/html/rfc6749#section-4.1.1 4.1.1> of the
-- specification.  This does not insert a leading @?@.
authorizationRequestParams
  :: OAuthProvider provider
  => OAuthConfig provider
  -> AuthorizationRequest provider
  -> OAuthState
  -> Text
authorizationRequestParams cfg req state =
  let
    provider = _authorizationRequest_provider req
    pCfg = _oAuthConfig_providers cfg $ _authorizationRequest_provider req
  in
  encode (queryParametersTextEncoder @Identity @Identity) $
  Map.toList $ fmap Just $ mconcat
    [ Map.singleton "response_type" $ case _providerConfig_responseType pCfg of
        AuthorizationResponseType_Code  -> "code"
        AuthorizationResponseType_Token -> "token"
    , Map.singleton "client_id" (unOAuthClientId . _providerConfig_clientId $ pCfg)
    , case _oAuthConfig_renderRedirectUri cfg of
        Nothing -> Map.empty
        Just render -> Map.singleton "redirect_uri" $
          render $ OAuthRoute_Redirect :/ (oAuthProviderId provider, Nothing)
    , case _authorizationRequest_scope req of
        [] -> Map.empty
        xs -> Map.singleton "scope" $ T.unwords xs
    , Map.singleton "state" (oAuthStateAsText state)
    ]
