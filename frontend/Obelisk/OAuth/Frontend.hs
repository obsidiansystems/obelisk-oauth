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

{-| Reflex component for handling `OAuth` oAuthFrontend.

-}
module Obelisk.OAuth.Frontend
  ( -- * Basic interface
    OAuthFrontendConfig (..)
  , HasOAuthFrontendConfig (..)
  , OAuthFrontend (..)
  , HasOAuthFrontend (..)
  , TokenGetter
  , makeOAuthFrontendExeCfg
  , makeOAuthFrontend
    -- * Needed constraints
  , SupportsOAuth
    -- * Implementation details (probably should not be exported here at all - use with care.)
  , StoreOAuth (..)
  , retrieveCode
  , doAuthorize
  , retrieveToken
  ) where

import Control.Lens
import Control.Monad.Fix (MonadFix)
import Control.Monad ((<=<), void)
import Control.Monad.IO.Class (MonadIO, liftIO)
import Data.Dependent.Sum (DSum ((:=>)))
import Data.Functor.Identity (Identity (..))
import Data.Functor.Identity (Identity)
import Data.Functor.Sum (Sum (..))
import Data.Text (Text)
import GHC.Generics (Generic)
import qualified GHCJS.DOM as DOM
import qualified GHCJS.DOM.Window as Window
import Language.Javascript.JSaddle (MonadJSM)
import Obelisk.Route (Encoder, PageName, R)
import Reflex
import qualified Data.Map as Map
import Data.These (These (..))
import Data.Align (alignWith)

import Obelisk.OAuth.Config (OAuthConfig (..), ProviderConfig (..), AuthorizationResponseType (..))
import Obelisk.OAuth.Provider (OAuthProvider (..), oAuthProviderFromIdErr)
import Obelisk.OAuth.Error (OAuthError (..))
import Obelisk.OAuth.Frontend.Internal (makeReflexLenses, tagOnPostBuild)
import Obelisk.OAuth.Frontend.Storage
import Obelisk.OAuth.AuthorizationRequest (authorizationRequestHref, AuthorizationRequest (..))
import Obelisk.OAuth.Route (OAuthRoute (..), AccessToken (..), RedirectUriParams (..), OAuthCode (..))
import Obelisk.OAuth.State (OAuthState, genOAuthState)
import Obelisk.OAuth.Api (OAuthRequest (..), OAuthBackendRequest (..))


data OAuthFrontendConfig provider t = OAuthFrontendConfig
  { _oAuthFrontendConfig_authorize :: Event t (AuthorizationRequest provider)
    -- ^ Initiate authorization. This will forward the user to the
    --   authorization provider/server - thus after triggering this event the user will
    --   leave the application. Make sure you to save any important data!
  , _oAuthFrontendConfig_route     :: Dynamic t (Maybe (R OAuthRoute))
    -- ^ Get route updates that are relevant to OAuth.
  }
  deriving Generic


data OAuthFrontend provider t = OAuthFrontend
  { _oAuthFrontend_authorized :: Event t (Either OAuthError (provider, AccessToken))
    -- ^ Event gets triggered after authorization is completed, with either an
    -- error or the token to be used for API requests.
  }
  deriving Generic

data OAuthResponse a = OAuthResponse (OAuthRequest a) a

type SupportsOAuth t m =
  ( Reflex t, MonadIO m, MonadHold t m, MonadJSM m, PostBuild t m
  , PerformEvent t m , MonadJSM (Performable m)
  , Requester t m, Request m ~ OAuthRequest, Response m ~ OAuthResponse
  )


-- | Make an `OAuthFrontend` provided with the needed configuration.
--
--   The browser's session storage is used for keeping track of the OAuth
--   state. The storage key `show $ StoreOAuth_State
--   _oAuthConfig_provider` is used for storing this state.
makeOAuthFrontend
  :: (SupportsOAuth t m, OAuthProvider provider)
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
  :: forall t m provider. (SupportsOAuth t m, OAuthProvider provider)
  => OAuthConfig provider
  -> OAuthFrontendConfig provider t
  -> m (Event t (Either OAuthError (provider, RedirectUriParams)))
retrieveCode sCfg (OAuthFrontendConfig onAuth route) = do

    onReqState <- storeStateOnRequest onAuth
    performEvent_ $ doAuthorize sCfg <$> onReqState

    onRoute <- fmapMaybe id <$> tagOnPostBuild route

    let
      (onErr, onParams) = fanEither $ getParams <$> onRoute

    onStoreResp <-
      requesting $ OAuthRequest_LoadState . oAuthProviderId . fst <$> onParams

    let
      onMStoredState = fmapMaybe id . ffor onStoreResp $ \case
        OAuthResponse (OAuthRequest_LoadState provId) mState -> Just (provId, mState)
        _ -> Nothing

    onParamsStored :: Event t ((provider, RedirectUriParams), Maybe OAuthState)
      <- getReqResp
          (oAuthProviderId . _authorizationRequest_provider . fst)
          onParams
          onMStoredState

    -- Clean up after ourselves:
    requesting_ $ OAuthRequest_RemoveState . oAuthProviderId . fst . fst <$> onParamsStored

    pure $ leftmost
      [ Left <$> onErr
      , uncurry checkState <$> onParamsStored
      ]

  where
    checkState _ Nothing = Left OAuthError_NoSessionState
    checkState ps@(_, RedirectUriParams c new) (Just old) = if new == old
      then Right ps
      else Left OAuthError_InvalidState

    getParams :: R OAuthRoute -> Either OAuthError (provider, RedirectUriParams)
    getParams = \case
      OAuthRoute_Redirect :=> Identity (providerId, Just pars) ->
        (, pars) <$> oAuthProviderFromIdErr providerId
      OAuthRoute_Redirect :=> Identity Nothing ->
        Left OAuthError_MissingCodeState


-- | Get an `OAuthState` to a request and make sure it is stored.
storeStateOnRequest
  :: forall m t provider
  . (Reflex t, MonadHold t m, MonadFix m, OAuthProvider provider)
  => Event t (AuthorizationRequest provider)
  -> m (Event t (AuthorizationRequest provider, OAuthState))
storeStateOnRequest onReq = do

  unsavedCode <- performEvent $ genOAuthState <$ onReq

  r <- requesting $ OAuthRequest_StoreState providerId <$> unsavedCode

  let
    onResp = fmapMaybe id . ffor r $ \case
      OAuthResponse (OAuthRequest_StoreState provId storedState) () -> Just (provId, storedState)
      _ -> Nothing

  getReqResp
    (oAuthProviderId . _authorizationRequest_provider)
    onReq
    onResp


-- | Build request uri and forward user to authorization server.
--
doAuthorize
  :: (MonadIO m, MonadJSM m, OAuthProvider provider)
  => OAuthConfig provider
  -> (AuthorizationRequest provider, OAuthState)
  -> m ()
doAuthorize sCfg (req, oState) = do

  let reqUri = authorizationRequestHref sCfg req oState

  w <- DOM.currentWindowUnchecked

  void $ Window.open w (Just reqUri) (Just ("_self" :: Text)) (Nothing :: Maybe Text)


-- | Retrieves access token based on redirect values.
retrieveToken
  :: (SupportsOAuth t m, OAuthProvider provider)
  => OAuthConfig provider
  -> Event t (provider, RedirectUriParams)
  -> m (Event t (Either OAuthError (provider, AccessToken)))
retrieveToken sCfg onParams = do
    let
      mkReq (p, ps) = OAuthRequest_Backend $ OAuthBackendRequest_GetToken (oAuthProviderId p) ps

      (onDirectToken, onParamsReq) = fanEither $ ffor onParams $ \ps@(provider, RedirectUriParams code state) ->
        let
          rType = _providerConfig_responseType . _oAuthConfig_providers sCfg $ provider
        in
          case rType of
            AuthorizationResponseType_Token -> Left (provider, AccessToken . unOAuthCode $ code)
            AuthorizationResponseType_Code  -> Right ps

    eTokenRsp <- requesting $ mkReq <$> onParamsReq
    let
      eToken = fmapMaybe id $ ffor eTokenRsp $ \case
        OAuthResponse (OAuthRequest_Backend (OAuthBackendRequest_GetToken provId _)) errToken ->
          Just $ (,) <$> oAuthProviderFromIdErr provId <*> errToken
        _ ->
          Nothing

    pure $ leftmost
      [ Right <$> onDirectToken
      , eToken
      ]


-- | Get a response munched together with it's corresponding request.
--
--   TODO: What to do with multiple identical requests?
getReqResp
  :: (Eq reqId, Ord reqId, MonadHold t m, Reflex t, MonadFix m)
  => (req -> reqId)
  -> Event t req
  -> Event t (reqId, resp)
  -> m (Event t (req, resp))
getReqResp getReqId onReq onResp = mdo

    reqs <- foldDyn id Map.empty $ mergeWith (.)
      [ ffor onResp $
          \(reqId, _) -> Map.delete reqId

      , ffor onReq insertReq
      ]

    -- Handle coincidence of request and response properly:
    pure $ fmapMaybe id $ alignWith buildResponse onReq $ attach (current reqs) onResp

  where
    insertReq r = Map.insert (getReqId r) r

    buildResponse = \case
      This _ -> Nothing
      That (cReqs, (reqId, res)) -> (, res) <$> Map.lookup reqId cReqs
      These req (cReqs, res) ->
        buildResponse $ That (insertReq req cReqs, res)
