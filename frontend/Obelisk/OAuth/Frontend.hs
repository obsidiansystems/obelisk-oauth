{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE FunctionalDependencies #-}
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
{-# LANGUAGE RecursiveDo #-}
{-# LANGUAGE TupleSections #-}
{-# LANGUAGE DeriveFunctor #-}

{-| Reflex component for handling `OAuth` oAuthFrontend.

-}
module Obelisk.OAuth.Frontend
  ( -- * Basic interface
    OAuthFrontendConfig (..)
  , OAuthFrontend (..)
  , makeOAuthFrontend
    -- * Needed constraints
  , SupportsOAuth
    -- * Implementation details (probably should not be exported here at all - use with care.)
  , retrieveCode
  , doAuthorize
  , retrieveToken
  ) where

import Control.Monad.Fix (MonadFix)
import Control.Monad (void)
import Control.Monad.IO.Class (MonadIO)
import Data.Dependent.Sum (DSum ((:=>)))
import Data.Functor.Identity (Identity (..))
import Data.Text (Text)
import GHC.Generics (Generic)
import qualified GHCJS.DOM as DOM
import qualified GHCJS.DOM.Window as Window
import Language.Javascript.JSaddle (MonadJSM)
import Obelisk.Route (R)
import Reflex

import Obelisk.OAuth.Config (OAuthConfig (..), ProviderConfig (..), AuthorizationResponseType (..))
import Obelisk.OAuth.Provider (IsOAuthProvider (..), oAuthProviderFromIdErr)
import Obelisk.OAuth.Error (OAuthError (..))
import Obelisk.OAuth.Frontend.Internal (tagOnPostBuild)
import Obelisk.OAuth.AuthorizationRequest (authorizationRequestHref, AuthorizationRequest (..))
import Obelisk.OAuth.Route (OAuthRoute (..), AccessToken (..), RedirectUriParams (..), OAuthCode (..))
import Obelisk.OAuth.State (OAuthState, genOAuthState)
import Obelisk.OAuth.Frontend.Command


data OAuthFrontendConfig provider t = OAuthFrontendConfig
  { _oAuthFrontendConfig_authorize :: Event t (AuthorizationRequest provider)
    -- ^ Initiate authorization. This will forward the user to the
    --   authorization provider/server - thus after triggering this event the user will
    --   leave the application. Make sure you to save any important data!
    --   TODO: Block multiple concurrent requests with error as this can't work
    --   because of the redirect and overrides.
  , _oAuthFrontendConfig_route     :: Dynamic t (Maybe (R OAuthRoute))
    -- ^ Get route updates that are relevant to OAuth.
  }
  deriving Generic


newtype OAuthFrontend provider t = OAuthFrontend
  { _oAuthFrontend_authorized :: Event t (Either OAuthError (provider, AccessToken))
    -- ^ Event gets triggered after authorization is completed, with either an
    -- error or the token to be used for API requests.
    -- TODO: Not only return access token, but also token type and scope.
  }
  deriving Generic


type SupportsOAuth t m provider =
  ( Reflex t, MonadIO m, MonadHold t m, MonadJSM m, PostBuild t m
  , PerformEvent t m , MonadJSM (Performable m), MonadFix m
  , Requester t m, Request m ~ Command provider, Response m ~ Identity
  , IsOAuthProvider provider
  )


-- | Make an `OAuthFrontend` provided with the needed configuration.
--
--   The browser's session storage is used for keeping track of the OAuth
--   state. The storage key `show $ StoreOAuth_State
--   _oAuthConfig_provider` is used for storing this state.
makeOAuthFrontend
  :: (SupportsOAuth t m provider)
  => OAuthConfig provider
  -> OAuthFrontendConfig provider t
  -> m (OAuthFrontend provider t)
makeOAuthFrontend sCfg cfg = do

  onErrParams <- retrieveCode sCfg cfg

  let (onErr, onParams) = fanEither onErrParams

  eToken <- retrieveToken sCfg onParams

  pure $ OAuthFrontend $ leftmost
    [ Left <$> onErr
    , eToken
    ]


-- | Takes care of issuing the initial authorization request and handling the
--   code response.
--
--   State will be properly generated and checked.
retrieveCode
  :: forall t m provider. (SupportsOAuth t m provider)
  => OAuthConfig provider
  -> OAuthFrontendConfig provider t
  -> m (Event t (Either OAuthError (provider, RedirectUriParams)))
retrieveCode sCfg (OAuthFrontendConfig onAuth route) = do

    onReqState <- getStoredStateOnRequest onAuth
    performEvent_ $ doAuthorize sCfg <$> onReqState

    onRoute <- fmapMaybe id <$> tagOnPostBuild route

    let
      (onErr, onParams) = fanEither $ getParams <$> onRoute

    onParamsVerified <-
      requestingIdentity $ ffor onParams $ \params -> do
        mOldState <- command_loadState $ fst params
        command_removeState $ fst params -- Clean up.
        pure $ checkState params mOldState

    pure $ leftmost
      [ Left <$> onErr
      , onParamsVerified
      ]

  where
    checkState _ Nothing = Left OAuthError_NoSessionState
    checkState ps@(_, RedirectUriParams _ new) (Just old) = if new == old
      then Right ps
      else Left OAuthError_InvalidState

    getParams :: R OAuthRoute -> Either OAuthError (provider, RedirectUriParams)
    getParams = \case
      OAuthRoute_Redirect :=> Identity (providerId, Just pars) ->
        (, pars) <$> oAuthProviderFromIdErr providerId
      OAuthRoute_Redirect :=> Identity (_, Nothing) ->
        Left OAuthError_MissingCodeState


-- | Get an `OAuthState` to a request and make sure it is stored.
getStoredStateOnRequest
  :: forall m t provider
  . (SupportsOAuth t m provider)
  => Event t (AuthorizationRequest provider)
  -> m (Event t (AuthorizationRequest provider, OAuthState))
getStoredStateOnRequest onReq = do

  onUnsavedState <- performEvent $ ffor onReq $ \req -> do
    s <- genOAuthState
    pure (req, s)

  requestingIdentity $ ffor onUnsavedState $ \rs@(req, s) -> do
    command_storeState (_authorizationRequest_provider req) s
    pure rs


-- | Build request uri and forward user to authorization server.
--
doAuthorize
  :: (MonadIO m, MonadJSM m, IsOAuthProvider provider)
  => OAuthConfig provider
  -> (AuthorizationRequest provider, OAuthState)
  -> m ()
doAuthorize sCfg (req, oState) = do

  let reqUri = authorizationRequestHref sCfg req oState

  w <- DOM.currentWindowUnchecked

  void $ Window.open w (Just reqUri) (Just ("_self" :: Text)) (Nothing :: Maybe Text)


-- | Retrieves access token based on redirect values.
retrieveToken
  :: (SupportsOAuth t m provider)
  => OAuthConfig provider
  -> Event t (provider, RedirectUriParams)
  -> m (Event t (Either OAuthError (provider, AccessToken)))
retrieveToken sCfg onParams =
  requestingIdentity $ ffor onParams $ \(provider, params) -> do

    let rType = _providerConfig_responseType . _oAuthConfig_providers sCfg $ provider

    case rType of
      AuthorizationResponseType_Token ->
        pure $ Right (provider, AccessToken . unOAuthCode . _redirectUriParams_code $ params)
      AuthorizationResponseType_Code  ->
        fmap (provider, ) <$> command_getToken provider params
