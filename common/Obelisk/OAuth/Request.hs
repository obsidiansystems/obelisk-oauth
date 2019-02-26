{-# LANGUAGE DeriveGeneric         #-}
{-# LANGUAGE FlexibleContexts      #-}
{-# LANGUAGE FlexibleInstances     #-}
{-# LANGUAGE GADTs                 #-}
{-# LANGUAGE KindSignatures        #-}
{-# LANGUAGE LambdaCase            #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE RankNTypes            #-}
{-# LANGUAGE ScopedTypeVariables   #-}
{-# LANGUAGE StandaloneDeriving    #-}
{-# LANGUAGE TemplateHaskell       #-}
{-# LANGUAGE TypeApplications      #-}
{-# LANGUAGE UndecidableInstances  #-}
{-| Creation of `Request`s going to the resource owner/ authorization server.

This module provides the means for easily creating a request to an
authorization server as specified in rfc6749.  More concrete, it provides the
means for creating the URI to the authorization server you are going to
redirect the user to, so he can be prompted for authorization by the resource
server (E.g. github).

Usually this redirect will be issued by the frontend as it has the means to
generate and hold on to the needed `OAuthState` via session storage for
example.
-}
module Obelisk.OAuth.Request
  ( -- * Types and classes
    AuthorizationResponseType (..)
  , OAuthClientId (..)
  , OAuthState
    -- * Build actual request
  , authorizationRequestHref
    -- * Helper functions
    --
    --   You should usually not need those and be fine with just `authorizationRequestHref`.
  , authorizationRequestParams
  , renderRedirectUri
  , renderRedirectUriRoute
  , redirectUriParamsEncoder
  ) where

import           Prelude               hiding ((.))

import           Control.Category      ((.))
import           Data.Functor.Identity (Identity (..))
import           Data.Functor.Sum      (Sum (..))
import qualified Data.Map              as Map
import           Data.Text             (Text)
import qualified Data.Text             as T

import           Obelisk.OAuth.Route   (OAuthClientId (..), OAuthRoute (..),
                                        redirectUriParamsEncoder)
import           Obelisk.OAuth.State   (OAuthState, oAuthStateAsText)
import           Obelisk.Route

import           Obelisk.OAuth.Config  (AuthorizationResponseType (..),
                                        OAuthConfig (..))


-- | Render the authorization request.
--
--   This should be all you need from this module in most cases.
authorizationRequestHref
  :: Encoder Identity Identity (R (Sum r a)) PageName -- ^ Backend route encoder
  -> OAuthConfig secret r -- ^ Configuration for building up request.
  -> OAuthState -- ^ The state for building the request URI.
  -> Text
     -- ^ Authorization grant request endpoint with query string
authorizationRequestHref enc cfg state =
  _oAuthConfig_providerUri cfg <> "?" <> authorizationRequestParams enc cfg state


-- | Turn an 'AuthorizationRequest' into query string parameters separated by
--   @&@. Key names are defined in
--
-- <https://tools.ietf.org/html/rfc6749#section-4.1.1 4.1.1> of the
-- specification.  This does not insert a leading @?@.
authorizationRequestParams
  :: Encoder Identity Identity (R (Sum r a)) PageName
     -- ^ Encoder for `_oAuthConfig_redirectUri`
  -> OAuthConfig secret r
     -- ^ Configruation for building parameters
  -> OAuthState
  -> Text
authorizationRequestParams enc cfg state = encode (queryParametersTextEncoder @Identity @Identity) $
  Map.toList $ fmap Just $ mconcat
    [ Map.singleton "response_type" $ case _oAuthConfig_responseType cfg of
        AuthorizationResponseType_Code  -> "code"
        AuthorizationResponseType_Token -> "token"
    , Map.singleton "client_id" (unOAuthClientId . _oAuthConfig_clientId $ cfg)
    , case _oAuthConfig_redirectUri cfg of
        Nothing -> Map.empty
        Just (b, r) -> Map.singleton "redirect_uri" $
          renderRedirectUri enc b r
    , case _oAuthConfig_scope cfg of
        [] -> Map.empty
        xs -> Map.singleton "scope" $ T.unwords xs
    , Map.singleton "state" (oAuthStateAsText state)
    ]


-- | Given the base URL  of the client application, a checked backend route
--   encoder (see 'checkEncoder'), render the redirect URI.
renderRedirectUri
  :: Encoder Identity Identity (R (Sum r a)) PageName -- ^ Checked backend route encoder
  -> Text -- ^ Application base url
  -> r (R OAuthRoute) -- ^ OAuth parent route
  -> Text -- ^ Rendered redirect url
renderRedirectUri enc base = (base <>) . renderRedirectUriRoute enc


-- | Given a checked backend route encoder (see 'checkEncoder'), and the
--   app-specific parent route under which the OAuth routes are nested, construct
--   the redirect URI's route (i.e., the path and query string parts).
renderRedirectUriRoute
  :: Encoder Identity Identity (R (Sum r a)) PageName
     -- ^ Checked backend route encoder
  -> r (R OAuthRoute)
     -- ^ OAuth parent route
  -> Text
     -- ^ Rendered route
renderRedirectUriRoute enc r =
  renderBackendRoute enc $ r :/ OAuthRoute_TransmitCode :/ Nothing
